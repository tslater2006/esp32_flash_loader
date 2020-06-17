/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package esp32_loader;

import java.io.IOException;
import java.util.*;

import esp32_loader.flash.ESP32Flash;
import esp32_loader.flash.ESP32Partition;
import generic.jar.ResourceFile;
import esp32_loader.flash.ESP32AppImage;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.Application;
import ghidra.framework.model.DomainObject;
import ghidra.framework.store.LockException;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.data.DataTypeConflictException;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedLongDataType;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.AddressSetPropertyMap;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import org.w3c.dom.*;
import javax.xml.parsers.*;
import java.io.*;
/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class esp32_loaderLoader extends AbstractLibrarySupportLoader {
	ESP32Flash parsedFlash = null;
	ESP32AppImage parsedAppImage = null;
	@Override
	public String getName() {

		// TODO: Name the loader. This name must match the name of the loader in the
		// .opinion
		// files.
		return "ESP32 Flash Image"; 
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		// TODO: Examine the bytes in 'provider' to determine if this loader can load
		// it. If it
		// can load it, return the appropriate load specifications.
		BinaryReader reader = new BinaryReader(provider, true);

		/* 2nd stage bootloader is at 0x1000, should start with an 0xE9 byte */
		if (reader.length() > 0x1000) {
			var magic = reader.readByte(0x1000);

			if ((magic & 0xFF) == 0xE9) {
				try {
					/* parse the flash... */
					parsedFlash = new ESP32Flash(reader);
					loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair(
							new LanguageID("Xtensa:LE:32:default"), new CompilerSpecID("default")), true));
				} catch (Exception ex) {
				}
			} else {
				/* maybe they fed us an app image directly */
				if ((reader.readByte(0x00) & 0xFF) == 0xE9) {
					/* App image magic is first byte */
					try {
						parsedAppImage = new ESP32AppImage(reader);
						loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair(
								new LanguageID("Xtensa:LE:32:default"), new CompilerSpecID("default")), true));
					} catch (Exception ex) {}
				}
			}
		}

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program,
			TaskMonitor monitor, MessageLog log) throws CancelledException, IOException {
		FlatProgramAPI api = new FlatProgramAPI(program, monitor);
		BinaryReader reader = new BinaryReader(provider, true);

		ESP32AppImage imageToLoad = null;
		if (parsedAppImage != null) {
			imageToLoad = parsedAppImage;
		} else {
			/* they probably gave us a firmware file, lets load that and get the partition they selected */
			var partOpt = (String) (options.get(0).getValue());

			ESP32Partition part = parsedFlash.GetPartitionByName(partOpt);
			try {
			imageToLoad = part.ParseAppImage();
			} catch(Exception ex) {}
		}
		
		
		try {
			AddressSetPropertyMap codeProp = program.getAddressSetPropertyMap("CodeMap");
			if (codeProp == null) {
				codeProp = program.createAddressSetPropertyMap("CodeMap");
			} 

			for (var x = 0; x < imageToLoad.SegmentCount; x++) {
				var curSeg = imageToLoad.Segments.get(x);

				FileBytes fileBytes = MemoryBlockUtils.createFileBytes(program, new ByteArrayProvider(curSeg.Data),
						0x00, curSeg.Length, monitor);

				var memBlock = program.getMemory().createInitializedBlock(
						curSeg.SegmentName + "_" + Integer.toHexString(curSeg.LoadAddress),
						api.toAddr(curSeg.LoadAddress), fileBytes, 0x00, curSeg.Length, false);
				memBlock.setPermissions(curSeg.IsRead, curSeg.IsWrite, curSeg.IsExecute);

				/* Mark Instruction blocks as code */
				if (curSeg.SegmentName.startsWith("I")) {
					codeProp.add(api.toAddr(curSeg.LoadAddress), api.toAddr(curSeg.LoadAddress + curSeg.Length));
				}

			}

			/* set the entry point */
			program.getSymbolTable().addExternalEntryPoint(api.toAddr(imageToLoad.EntryAddress));
			
			/* Create Peripheral Device Memory Blocks */
			if (imageToLoad.IsEsp32S2) {
				log.appendMsg("Process esp32s2 svd");
			}	
			processSVD(program, api,imageToLoad.IsEsp32S2);
			

		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// TODO: Load the bytes from 'provider' into the 'program'.
	}

	private void processSVD(Program program, FlatProgramAPI api,boolean isESP32S2) throws Exception {
		// TODO Auto-generated method stub
		List<ResourceFile> svdFileList =  Application.findFilesByExtensionInMyModule("svd");
		if (svdFileList.size() > 0) {
			/* grab the first svd file ... */
			String svdFile = svdFileList.get(0).getAbsolutePath();
			boolean isFound = svdFile.indexOf("esp32s2") !=-1? true: false;
			if (isESP32S2) {
				if (!isFound) {
					svdFileList.get(1).getAbsolutePath();
				} 
			} else  {
				if (isFound) {
					svdFileList.get(1).getAbsolutePath();
				} 
			}
			DocumentBuilderFactory factory =
			DocumentBuilderFactory.newInstance();
			DocumentBuilder builder = factory.newDocumentBuilder();
			
			Document doc = builder.parse(svdFile);
			
			Element root = doc.getDocumentElement();
			
			NodeList peripherals = root.getElementsByTagName("peripheral");
			for(var x=0; x < peripherals.getLength(); x++) {
				processPeripheral(program, api, (Element)peripherals.item(x));
			}
		}
	}

	private void processPeripheral (Program program, FlatProgramAPI api, Element peripheral) throws DuplicateNameException, InvalidInputException, CodeUnitInsertionException, DataTypeConflictException, LockException, MemoryConflictException, AddressOverflowException {
		String baseAddrString = ((Element)(peripheral.getElementsByTagName("baseAddress").item(0))).getTextContent();
		int baseAddr = Integer.decode(baseAddrString);
		
		String peripheralName = ((Element)(peripheral.getElementsByTagName("name").item(0))).getTextContent();
		Element addressBlock = (Element) peripheral.getElementsByTagName("addressBlock").item(0);
		int size = Integer.decode(addressBlock.getElementsByTagName("size").item(0).getTextContent());
		
		registerPeripheralBlock(program, api, baseAddr, baseAddr + size - 1, peripheralName);
		
		StructureDataType struct = new StructureDataType(peripheralName, size);
		
		NodeList registers = peripheral.getElementsByTagName("register");
		
		for (var x = 0; x < registers.getLength(); x++) {
			Element register = (Element)registers.item(x);
			String registerName = ((Element)(register.getElementsByTagName("name").item(0))).getTextContent();
			String offsetString = ((Element)(register.getElementsByTagName("addressOffset").item(0))).getTextContent();
			int offsetValue = Integer.decode(offsetString);
			
			struct.replaceAtOffset(offsetValue, new UnsignedLongDataType() , 4, registerName, "");
			
		}
		
		var dtm = program.getDataTypeManager();
		var space = program.getAddressFactory().getDefaultAddressSpace();
		var listing = program.getListing();
		var symtbl = program.getSymbolTable();
		var namespace = symtbl.getNamespace("Peripherals",null);
		if (namespace == null) {
			namespace = program.getSymbolTable().createNameSpace(null, "Peripherals", SourceType.ANALYSIS);
		}
		
		var addr = space.getAddress(baseAddr);
		dtm.addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER);
		listing.createData( addr, struct);
		symtbl.createLabel(addr, peripheralName, namespace, SourceType.USER_DEFINED );
	}
	
	private void registerPeripheralBlock(Program program, FlatProgramAPI api, int startAddr, int endAddr, String name)
			throws LockException, DuplicateNameException, MemoryConflictException, AddressOverflowException {
		// TODO Auto-generated method stub
		var block = program.getMemory().createUninitializedBlock(name, api.toAddr(startAddr), endAddr - startAddr + 1, false);
		block.setRead(true);
		block.setWrite(true);

		/*
		 * var memBlock = program.getMemory().createInitializedBlock(curSeg.SegmentName
		 * + "_" + Integer.toHexString(curSeg.LoadAddress),
		 * api.toAddr(curSeg.LoadAddress), fileBytes, 0x00, curSeg.Length, false);
		 * memBlock.setPermissions(curSeg.IsRead, curSeg.IsWrite, curSeg.IsExecute);
		 */
	}


	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec, DomainObject domainObject,
			boolean isLoadIntoProgram) {
		List<Option> list = new ArrayList<Option>();

		if (parsedFlash != null) {
			// TODO: If this loader has custom options, add them to 'list'
			list.add(new PartitionOption(parsedFlash));
		}
		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {

		// TODO: If this loader has custom options, validate them here. Not all options
		// require
		// validation.
		return null;
		// return super.validateOptions(provider, loadSpec, options, program);
	}
}

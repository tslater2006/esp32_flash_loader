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
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.util.AddressSetPropertyMap;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
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
			registerPeripheralBlock(program, api, 0x3FF00000, 0x3FF00FFF, "DPort Register");
			registerPeripheralBlock(program, api, 0x3FF01000, 0x3FF01FFF, "AES Accelerator");
			registerPeripheralBlock(program, api, 0x3FF02000, 0x3FF02FFF, "RSA Accelerator");
			registerPeripheralBlock(program, api, 0x3FF03000, 0x3FF03FFF, "SHA Accelerator");
			registerPeripheralBlock(program, api, 0x3FF04000, 0x3FF04FFF, "Secure Boot");
			registerPeripheralBlock(program, api, 0x3FF10000, 0x3FF13FFF, "Cache MMU Table");
			registerPeripheralBlock(program, api, 0x3FF1F000, 0x3FF1FFFF, "PID Controller");
			registerPeripheralBlock(program, api, 0x3FF40000, 0x3FF40FFF, "UART0");
			registerPeripheralBlock(program, api, 0x3FF42000, 0x3FF42FFF, "SPI1");
			registerPeripheralBlock(program, api, 0x3FF43000, 0x3FF43FFF, "SPI0");
			registerPeripheralBlock(program, api, 0x3FF44000, 0x3FF44FFF, "GPIO");
			registerPeripheralBlock(program, api, 0x3FF48000, 0x3FF48FFF, "RTC");
			registerPeripheralBlock(program, api, 0x3FF49000, 0x3FF49FFF, "IO MUX");
			registerPeripheralBlock(program, api, 0x3FF4B000, 0x3FF4BFFF, "SDIO Slave1");
			registerPeripheralBlock(program, api, 0x3FF4C000, 0x3FF4CFFF, "UDMA1");
			registerPeripheralBlock(program, api, 0x3FF4F000, 0x3FF4FFFF, "I2S0");
			registerPeripheralBlock(program, api, 0x3FF50000, 0x3FF50FFF, "UART1");
			registerPeripheralBlock(program, api, 0x3FF53000, 0x3FF53FFF, "I2C0");
			registerPeripheralBlock(program, api, 0x3FF54000, 0x3FF54FFF, "UDMA0");
			registerPeripheralBlock(program, api, 0x3FF55000, 0x3FF55FFF, "SDIO Slave2");
			registerPeripheralBlock(program, api, 0x3FF56000, 0x3FF56FFF, "RMT");
			registerPeripheralBlock(program, api, 0x3FF57000, 0x3FF57FFF, "PCNT");
			registerPeripheralBlock(program, api, 0x3FF58000, 0x3FF58FFF, "SDIO Slave3");
			registerPeripheralBlock(program, api, 0x3FF59000, 0x3FF59FFF, "LED PWM");
			registerPeripheralBlock(program, api, 0x3FF5A000, 0x3FF5AFFF, "Efuse Controller");
			registerPeripheralBlock(program, api, 0x3FF5B000, 0x3FF5BFFF, "Flash Encryption");
			registerPeripheralBlock(program, api, 0x3FF5E000, 0x3FF5EFFF, "PWM0");
			registerPeripheralBlock(program, api, 0x3FF5F000, 0x3FF5FFFF, "TIMG0");
			registerPeripheralBlock(program, api, 0x3FF60000, 0x3FF60FFF, "TIMG1");
			registerPeripheralBlock(program, api, 0x3FF64000, 0x3FF64FFF, "SPI2");
			registerPeripheralBlock(program, api, 0x3FF65000, 0x3FF65FFF, "SPI3");
			registerPeripheralBlock(program, api, 0x3FF66000, 0x3FF66FFF, "SYSCON");
			registerPeripheralBlock(program, api, 0x3FF67000, 0x3FF67FFF, "I2C1");
			registerPeripheralBlock(program, api, 0x3FF68000, 0x3FF68FFF, "SDMMC");
			registerPeripheralBlock(program, api, 0x3FF69000, 0x3FF6AFFF, "EMAC");
			registerPeripheralBlock(program, api, 0x3FF6C000, 0x3FF6CFFF, "PWM1");
			registerPeripheralBlock(program, api, 0x3FF6D000, 0x3FF6DFFF, "I2S1");
			registerPeripheralBlock(program, api, 0x3FF6E000, 0x3FF6EFFF, "UART2");
			registerPeripheralBlock(program, api, 0x3FF6F000, 0x3FF6FFFF, "PWM2");
			registerPeripheralBlock(program, api, 0x3FF70000, 0x3FF70FFF, "PWM3");
			registerPeripheralBlock(program, api, 0x3FF75000, 0x3FF75FFF, "RNG");
			
			
			processSVD(program, api);
			

		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// TODO: Load the bytes from 'provider' into the 'program'.
	}

	private void processSVD(Program program, FlatProgramAPI api) throws Exception {
		// TODO Auto-generated method stub
		List<ResourceFile> svdFileList =  Application.findFilesByExtensionInMyModule("svd");
		if (svdFileList.size() > 0) {
			/* grab the first svd file ... */
			String svdFile = svdFileList.get(0).getAbsolutePath();
			DocumentBuilderFactory factory =
			DocumentBuilderFactory.newInstance();
			DocumentBuilder builder = factory.newDocumentBuilder();
			
			Document doc = builder.parse(svdFile);
			
			Element root = doc.getDocumentElement();
			
			NodeList peripherals = root.getElementsByTagName("peripheral");
			for(var x=0; x < peripherals.getLength(); x++) {
				processPeripheral((Element)peripherals.item(x));
			}
		}
	}

	private void processPeripheral (Element peripheral) {
		String baseAddrString = ((Element)(peripheral.getElementsByTagName("baseAddress").item(0))).getTextContent();
		int baseAddr = Integer.decode(baseAddrString);
		
		NodeList registers = peripheral.getElementsByTagName("register");
		
		for (var x = 0; x < registers.getLength(); x++) {
			Element register = (Element)registers.item(x);
			String registerName = ((Element)(register.getElementsByTagName("name").item(0))).getTextContent();
			String offsetString = ((Element)(register.getElementsByTagName("addressOffset").item(0))).getTextContent();
			int offsetValue = Integer.decode(offsetString);
			
			addRegister(registerName, baseAddr + offsetValue);
			
		}
	}
	
	private void addRegister(String name, int address) {
		
	}
	
	private void registerPeripheralBlock(Program program, FlatProgramAPI api, int startAddr, int endAddr, String name)
			throws LockException, DuplicateNameException, MemoryConflictException, AddressOverflowException {
		// TODO Auto-generated method stub
		program.getMemory().createUninitializedBlock(name, api.toAddr(startAddr), endAddr - startAddr, false);

		markDataForPeripheral(program, api, startAddr);

		/*
		 * var memBlock = program.getMemory().createInitializedBlock(curSeg.SegmentName
		 * + "_" + Integer.toHexString(curSeg.LoadAddress),
		 * api.toAddr(curSeg.LoadAddress), fileBytes, 0x00, curSeg.Length, false);
		 * memBlock.setPermissions(curSeg.IsRead, curSeg.IsWrite, curSeg.IsExecute);
		 */
	}

	private void markDataForPeripheral(Program program, FlatProgramAPI api, int startAddr) {
		// TODO Auto-generated method stub

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

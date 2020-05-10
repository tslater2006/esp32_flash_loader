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
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class esp32_loaderLoader extends AbstractLibrarySupportLoader {
	ESP32Flash parsedFlash = null;
	@Override
	public String getName() {

		// TODO: Name the loader.  This name must match the name of the loader in the .opinion 
		// files.

		return "ESP32 Flash Image";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		// TODO: Examine the bytes in 'provider' to determine if this loader can load it.  If it 
		// can load it, return the appropriate load specifications.
		BinaryReader reader = new BinaryReader(provider, true);
		
		/* 2nd stage bootloader is at 0x1000, should start with an 0xE9 byte */
		if (reader.length() > 0x1000) {
			var magic = reader.readByte(0x1000);
			
			if ((magic & 0xFF) == 0xE9) {
				try {
					/* parse the flash... */
					parsedFlash = new ESP32Flash(reader);
					if (parsedFlash.SecondaryBootloader != null) {
						loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair(new LanguageID("Xtensa:LE:32:default"), new CompilerSpecID("default")), true));
					}
				} catch (Exception ex) {}				
			}
		}
        
		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {

		// TODO: Load the bytes from 'provider' into the 'program'.
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list = new ArrayList<Option>();
		
		if (parsedFlash != null) {
		// TODO: If this loader has custom options, add them to 'list'
			list.add(new PartitionOption(parsedFlash));
		}
		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {

		// TODO: If this loader has custom options, validate them here.  Not all options require
		// validation.
		return null;
		//return super.validateOptions(provider, loadSpec, options, program);
	}
}

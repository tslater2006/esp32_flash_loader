package esp32_loader.flash;

import java.io.IOException;
import java.util.ArrayList;

import ghidra.app.util.bin.BinaryReader;

public class ESP32Flash {
	public ESP32AppImage SecondaryBootloader;
	public ArrayList<ESP32Partition> Partitions = new ArrayList<ESP32Partition>();
	
	public ESP32Flash(BinaryReader reader) throws IOException {
		
		/* first 0x1000 bytes are empty */
		byte[] skipped = reader.readNextByteArray(0x1000);
		
		/* next up is the 2nd stage bootloader, up to 0x7000 in size */
		SecondaryBootloader = new ESP32AppImage(reader);
		
		var t = new ESP32Partition();
		t.Name = "test 1";
		t.Type = ESP32_PARTITION_TYPE.APP_IMAGE;
		Partitions.add(t);
		
		t = new ESP32Partition();
		t.Name = "test 2";
		t.Type = ESP32_PARTITION_TYPE.APP_IMAGE;
		Partitions.add(t);
		
	}
	
	
}

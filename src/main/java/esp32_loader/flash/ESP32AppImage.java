package esp32_loader.flash;

import java.io.IOException;
import java.util.ArrayList;

import ghidra.app.util.bin.BinaryReader;

public class ESP32AppImage {
	public byte SegmentCount;
	public int EntryAddress;
	public boolean HashAppended;
	
	public ArrayList<ESP32AppSegment> Segments = new ArrayList<ESP32AppSegment>();
	
	public ESP32AppImage (BinaryReader reader) throws IOException {
		var magic = reader.readNextByte();
		this.SegmentCount = reader.readNextByte();
		reader.readNextByte(); // SPI Byte
		reader.readNextByte(); // SPI Size
		this.EntryAddress = reader.readInt(0x04);

		reader.readNextByte(); // WP Pin
        reader.readNextByteArray(3); // SPIPinDrv
        reader.readNextShort(); //Chip ID
        reader.readNextByte(); //MinChipRev
        reader.readNextByteArray(8); // Reserved
        this.HashAppended = (reader.readNextByte() == 0x01);
		
		
		for(var x =0 ;x < this.SegmentCount; x++) {
			Segments.add(new ESP32AppSegment(reader));
		}
	}
}

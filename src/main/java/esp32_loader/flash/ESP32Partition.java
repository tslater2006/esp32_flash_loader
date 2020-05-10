package esp32_loader.flash;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;

public class ESP32Partition {
	public String Name;
	public byte Type;
	public byte SubType;
	public int Offset;
	public int Length;
	public int FirstBytes;
	public byte[] Data;
	
	public ESP32Partition(BinaryReader reader) throws IOException {
		// TODO Auto-generated constructor stub
		
		reader.readNextShort(); // magic 
        Type = reader.readNextByte();
        SubType = reader.readNextByte();
        Offset = reader.readNextInt();
        Length = reader.readNextInt();
        Name = reader.readNextAsciiString(20);
		FirstBytes = reader.readInt(Offset);
	}
	
	public void LoadData(BinaryReader reader) throws IOException {
		Data = reader.readByteArray(Offset, Length);
	}
	
}

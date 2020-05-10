package esp32_loader.flash;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;

public class ESP32AppSegment {

	public int PhysicalOffset;
    public int LoadAddress;
    public int Length;
    public byte[] Data;
    
    public boolean IsRead = false;
    public boolean IsWrite = false;
    public boolean IsExecute = false;
    public String SegmentName;
    
	public ESP32AppSegment(ESP32AppImage app, BinaryReader reader) throws IOException {
		// TODO Auto-generated constructor stub
		LoadAddress = reader.readNextInt();
        Length = reader.readNextInt();
        Data = reader.readNextByteArray(Length);
        /* fully consume the segment */
        
        
        /* determine access type via memory map */
        if( LoadAddress >= 0x40800000 && LoadAddress <= 0x40800000 + 4194304) {
        	IsExecute = true;
        	IsRead = true;
        	SegmentName = "IROM0";
        	return;
        }
        
        if( LoadAddress >= 0x40000000 && LoadAddress <= 0x40000000 + 4194304) {
        	IsExecute = true;
        	IsRead = true;
        	IsWrite = true;
        	SegmentName = "IRAM0";
        	return;
        }
        
        if( LoadAddress >= 0x40400000 && LoadAddress <= 0x40400000 + 4194304) {
        	IsExecute = true;
        	IsRead = true;
        	IsWrite = true;
        	SegmentName = "IRAM1";
        	return;
        }
        
        if( LoadAddress >= 0x3F400000 && LoadAddress <= 0x3F400000 + 4194304) {
        	IsExecute = false;
        	IsRead = true;
        	IsWrite = false;
        	SegmentName = "DROM0";
        	return;
        }
        
        if( LoadAddress >= 0x3FF80000 && LoadAddress <= 0x3FF80000 + 524288) {
        	IsExecute = false;
        	IsRead = true;
        	IsWrite = true;
        	SegmentName = "DRAM0";
        	return;
        }
        
        if( LoadAddress >= 0x3F800000 && LoadAddress <= 0x3F800000 + 4194304) {
        	IsExecute = false;
        	IsRead = true;
        	IsWrite = true;
        	SegmentName = "DRAM1";
        	return;
        }        
	}

}

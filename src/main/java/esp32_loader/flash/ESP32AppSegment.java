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
    public boolean IsEsp32 = false;
    
	public ESP32AppSegment(ESP32AppImage app, BinaryReader reader, boolean isEsp32S2) throws IOException {
		// TODO Auto-generated constructor stub
		IsEsp32=isEsp32S2;
		LoadAddress = reader.readNextInt();
        Length = reader.readNextInt();
        Data = reader.readNextByteArray(Length);
        /* fully consume the segment */
        if (isEsp32S2) {
			
			/* determine access type via memory map */
			/*
				Loading section .flash.rodata, size 0x576c lma 0x3f000020   DROM0
				Loading section .dram0.data, size 0x1e74 lma 0x3ffbe150
				Loading section .iram0.vectors, size 0x403 lma 0x40024000
				Loading section .iram0.text, size 0x9d40 lma 0x40024404
				Loading section .flash.text, size 0x147f7 lma 0x40080020
			*/
	                // OK
			if( LoadAddress >= 0x3FFB0000 && LoadAddress <= 0x3FFB7FFF  ) {
				IsExecute = true;
				IsRead = true;
				IsWrite = true;
				SegmentName = "DRAM0";
				return;
			}

			//OK
			if( LoadAddress >= 0x3FFB8000 && LoadAddress <= 0x3FFFFFFF  ) {
				IsExecute = true;
				IsRead = true;
				IsWrite = true;
				SegmentName = "DRAM1";
				return;
			}
			
			// OK
			if( LoadAddress >= 0x40080000 && LoadAddress <= 0x40080000 + 4194304) {
				IsExecute = true;
				IsRead = true;
				SegmentName = "IF_TXT";
				return;
			}
			// OK
			if( LoadAddress >= 0x40020000 && LoadAddress <= 0x40027FFF  ) {
				IsExecute = true;
				IsRead = true;
				IsWrite = true;
				SegmentName = "IRAM0";
				return;
			}
			// OK
			if( LoadAddress >= 0x40028000 && LoadAddress <= 0x4006FFFF) {
				IsExecute = true;
				IsRead = true;
				IsWrite = true;
				SegmentName = "IRAM1";
				return;
			}
			
			// OK
			if( LoadAddress >= 0x3F000000 && LoadAddress <= 0x3F3F0000) {
				IsExecute = false;
				IsRead = true;
				IsWrite = false;
				SegmentName = "DF_ROA";
				return;
			}
			
			// ???
			/*
			if( LoadAddress >= 0x3F080000 && LoadAddress <= 0x3F080000 + 524288) {
				IsExecute = false;
				IsRead = true;
				IsWrite = true;
				SegmentName = "DRAM0";
				return;
			}
			*/
			if( LoadAddress >= 0x3F800000 && LoadAddress <= 0x3F800000 + 4194304) {
				IsExecute = false;
				IsRead = false;
				IsWrite = true;
				SegmentName = "F_DATA";
				return;
			}        

			IsExecute = true;
			IsRead = true;
			IsWrite = true;
			SegmentName = "IRAM";
			return;


		} else {
			
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

}

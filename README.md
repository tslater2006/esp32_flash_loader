# flash loader plugin for ghidra

Build with gradle

    export GHIDRA_INSTALL_DIR=/opt/ghidra/
    gradle
    
Put the ./dist/ghidra_9.1_DEV_20200613_esp32_flash_loader.zip
Into /opt/ghidra/Extensions/Ghidra/
Then enable the extension

If loading an elf file, load svd manually before doing analysis

https://leveldown.de/blog/svd-loader/
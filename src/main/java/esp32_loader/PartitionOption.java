package esp32_loader;

import java.awt.*;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.util.ArrayList;

import docking.widgets.combobox.GComboBox;
import esp32_loader.flash.ESP32Flash;
import ghidra.app.util.Option;

public class PartitionOption extends Option implements ItemListener {

	ESP32Flash parsedFlash;
	GComboBox<String> cb = new GComboBox<String>();

	public PartitionOption(ESP32Flash parsedFlash) {
		super("App Partition", "factory", String.class, "-partition");
		// TODO Auto-generated constructor stub
		this.parsedFlash = parsedFlash;
	}

	@Override
	public Component getCustomEditorComponent() {

		if (parsedFlash.SecondaryBootloader != null) {
			cb.addItem("Bootloader");
		}

		if (parsedFlash.Partitions.size() > 0) {
			cb.setName(getName());

			for (var x = 0; x < parsedFlash.Partitions.size(); x++) {
				/* Only add "App" partitions */
				var curPart = parsedFlash.Partitions.get(x);
				if (curPart.Type == 0x00) {

					if (curPart.SubType >= 0x10 && curPart.SubType <= 0x1F) {
						/* This is an OTA partition, check its StartBytes for a validity smell test */
						if (curPart.FirstBytes != -1) {
							cb.addItem(curPart.Name);
						}
					} else {
						cb.addItem(curPart.Name);
					}
				}
			}

			cb.setSelectedItem(parsedFlash.Partitions.get(0));
			cb.addItemListener(this);

			return cb;
		}

		return null;
	}

	public void itemStateChanged(ItemEvent evt) {
		setValue(cb.getSelectedItem());
	}

	@Override
	public Option copy() {
		// TODO Auto-generated method stub
		PartitionOption opt = new PartitionOption(parsedFlash);
		opt.setValue(this.getValue());
		return opt;
	}
}

package esp32_loader;

import java.awt.*;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.util.ArrayList;

import docking.widgets.combobox.GComboBox;
import esp32_loader.flash.ESP32Flash;
import esp32_loader.flash.ESP32_PARTITION_TYPE;
import ghidra.app.util.Option;

public class PartitionOption extends Option implements ItemListener{

	ESP32Flash parsedFlash;
	GComboBox<String> cb = new GComboBox<String>();
	public PartitionOption(ESP32Flash parsedFlash) {
		super("App Partition", "factory", String.class, "-partition");
		// TODO Auto-generated constructor stub
		this.parsedFlash = parsedFlash;
	}
	
	@Override
	public Component getCustomEditorComponent() {
		
		if (parsedFlash.Partitions.size() > 0) {
			cb.setName(getName());
			
			for(var x =0; x < parsedFlash.Partitions.size();x ++) {
				if (parsedFlash.Partitions.get(x).Type == ESP32_PARTITION_TYPE.APP_IMAGE) {
					cb.addItem(parsedFlash.Partitions.get(x).Name);	
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

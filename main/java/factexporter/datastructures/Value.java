package factexporter.datastructures;

import factexporter.datastructures.Storage.StorageType;

public class Value 
{
	private int size;
	private Storage storage;
	private String name;
	private int index;
	
	public Value(String name, String value, int size, int index, Storage storage) 
	{
		this.name = name;
		this.index = index;
		this.name = name;
		this.storage = storage;
	}
	
	public static Value createParameter(String name, int size, int index, Storage storage) {
		return new Value(name, "", size, index, storage);
	}
	
	public static Value createVariable(String name, int size, Storage storage) {
		return new Value(name, "", size,0, storage);
	}
	
	public static Value createConstant(String name, String value, int size, Storage storage) {
		return new Value(name, value, size,0, storage);
	}
	
	public static Value createOtherValue() {
		return new Value("","",0,0,null);
	}
	
	protected Value(int size, Storage storage) 
	{
		this.size = size;
		this.storage = storage;
	}
	
	public boolean inRegister()
	{
		return storage.getStorageType() == StorageType.REGISTER;
	}
	
	public int size() 
	{
		return size;
	}
	
	public String name() {
		return name;
	}
	
	
	public Storage getStorage() {
		return storage;
	}
	
	public int getIndex() {
		return index;
	}
}

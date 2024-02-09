package factexporter.datastructures;

public class Storage 
{
	private String name;
	private int offset;
	private StorageType storageType;
	
	public enum StorageType {
		REGISTER,
		STACK
	}
	
	Storage(StorageType storageType, String name, int offset) 
	{
		this.storageType = storageType;
		this.name = name;
		this.offset = offset;
	}
	
	public static Storage createRegister(String name) {
		return new Storage(StorageType.REGISTER, name, 0);
	}
	
	public static Storage createStack(int offset) {
		return new Storage(StorageType.STACK, "STACK", offset);
	}
	
	public StorageType getStorageType() {
		return this.storageType;
	}
	
	public String getName() 
	{
		return name;
	}
	
	public int getOffset() {
		return offset;
	}
}

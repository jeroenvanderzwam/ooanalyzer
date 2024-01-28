package factexporter.datastructures;

public abstract class Value 
{
	protected final int size;
	protected final Storage storage;
	
	protected Value(int size, Storage storage) 
	{
		this.size = size;
		this.storage = storage;
	}
	
	public int size() 
	{
		return size;
	}
	
	public abstract String value();
	
	public abstract String name();
	
	public abstract String toString();
	
	public abstract Storage storage();
}

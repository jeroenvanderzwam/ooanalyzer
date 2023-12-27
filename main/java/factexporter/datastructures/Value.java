package factexporter.datastructures;

public abstract class Value 
{
	protected final int size;
	
	protected Value(int size) 
	{
		this.size = size;
	}
	
	public int size() 
	{
		return size;
	}
	
	public abstract String toString();
}

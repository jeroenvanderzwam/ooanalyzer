package sourcecode;

public abstract class Value 
{
	protected final int _size;
	
	protected Value(int size) 
	{
		_size = size;
	}
	
	public int size() 
	{
		return _size;
	}
}

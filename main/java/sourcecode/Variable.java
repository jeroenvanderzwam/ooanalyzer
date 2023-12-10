package sourcecode;

public class Variable extends Value
{
	private final String _name;
	
	public Variable(String name, int size) 
	{
		super(size);
		_name = name;
	}
	
	public String name() 
	{
		return _name;
	}
	
	@Override
	public String toString()
	{
		return "%s::%s".formatted(_name, _size);
	}

}

package sourcecode;

public class Constant extends Value
{
	private final String _value;
	
	public Constant(String value, int size) 
	{
		super(size);
		_value = value;
	}
	
	public String value() 
	{
		return _value;
	}
	
	@Override
	public String toString()
	{
		return "%s::%s".formatted(_value, _size);
	}
}

package sourcecode;

public class Constant extends Value
{
	private final String value;
	
	public Constant(String val, int size) 
	{
		super(size);
		value = val;
	}
	
	public String value() 
	{
		return value;
	}
	
	@Override
	public String toString()
	{
		return "%s::%s".formatted(value, size);
	}
}

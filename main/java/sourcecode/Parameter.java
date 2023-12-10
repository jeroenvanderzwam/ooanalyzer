package sourcecode;

public class Parameter extends Value
{
	private final Register _register;
	private final int _index;
	private final String _name;
	
	public Parameter(String name, int size, int index, Register register) 
	{
		super(size);
		_index = index;
		_register = register;
		_name = name;
	}

	public String name() 
	{
		return _name;
	}
	
	public boolean inRegister()
	{
		return _register != null;
	}
	
	public Register register() 
	{
		return _register;
	}
	
	public int index() 
	{
		return _index;
	}
	
	@Override
	public String toString()
	{
		return _name;
	}
}

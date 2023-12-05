package factexporter;

public class Parameter 
{
	private Register _register;
	private int _index;
	private String _name;
	
	public Parameter(String name, int index, Register register) 
	{
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
}

package sourcecode;

public class Register extends Storage
{
	private final String name;
	
	public Register(String name) 
	{
		this.name = name;
	}
	
	public String name() 
	{
		return name;
	}
}

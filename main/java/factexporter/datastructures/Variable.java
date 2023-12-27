package factexporter.datastructures;

public class Variable extends Value
{
	private final String name;
	
	public Variable(String name, int size) 
	{
		super(size);
		this.name = name;
	}
	
	public String name() 
	{
		return name;
	}
	
	@Override
	public String toString()
	{
		return "%s::%s".formatted(name, size);
	}

}

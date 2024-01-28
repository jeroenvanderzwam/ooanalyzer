package factexporter.datastructures;

public class Variable extends Value
{
	private final String name;
	
	public Variable(String name, String value, int size, Storage storage) 
	{
		super(size, storage);
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

	@Override
	public String value() {
		return null;
	}

	@Override
	public Storage storage() {
		return storage;
	}

}

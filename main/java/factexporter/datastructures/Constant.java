package factexporter.datastructures;

public class Constant extends Value
{
	private final String value;
	private final String name;
	
	public Constant(String name, String val, int size, Storage storage) 
	{
		super(size, storage);
		value = val;
		this.name = name;
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

	@Override
	public String name() {
		return name;
	}

	@Override
	public Storage storage() {
		return storage;
	}
}

package factexporter.datastructures;

public class Parameter extends Value
{
	private final int index;
	private final String name;
	
	public Parameter(String name, int size, int index, Storage storage) 
	{
		super(size, storage);
		this.index = index;
		this.name = name;
	}

	public String name() 
	{
		return name;
	}
	
	public boolean inRegister()
	{
		return (storage instanceof Register);
	}
	
	@Override
	public Storage storage() 
	{
		return storage;
	}
	
	public int index() 
	{
		return index;
	}
	
	@Override
	public String toString()
	{
		return name;
	}

	@Override
	public String value() {
		return null;
	}
}

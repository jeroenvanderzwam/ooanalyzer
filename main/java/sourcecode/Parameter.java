package sourcecode;

public class Parameter extends Value
{
	private final Storage storage;
	private final int index;
	private final String name;
	
	public Parameter(String name, int size, int index, Storage storage) 
	{
		super(size);
		this.index = index;
		this.storage = storage;
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
	
	public Storage register() 
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
}

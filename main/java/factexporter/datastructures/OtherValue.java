package factexporter.datastructures;

public class OtherValue extends Value 
{

	public OtherValue() 
	{
		super(0, null);
	}
	
	@Override
	public String toString() 
	{
		return "Other";
	}

	@Override
	public String value() {
		return "Don't know";
	}

	@Override
	public String name() {
		return "Don't know";
	}

	@Override
	public Storage storage() {
		return null;
	}

}

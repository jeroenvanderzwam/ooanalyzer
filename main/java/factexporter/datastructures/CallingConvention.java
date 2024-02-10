package factexporter.datastructures;

public class CallingConvention 
{
	private final String name;
	
	public CallingConvention(String n) 
	{
		name = n;
	}
	
	public String name() 
	{
		return name;
	}

	public static CallingConvention createInvalidCallingConvention() {
		return new CallingConvention("invalid");
	}
}

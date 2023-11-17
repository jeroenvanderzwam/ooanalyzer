package noCallsBefore;

public class UnknownArgument implements Argument
{
	private String value;
	private String dataType;
	
	UnknownArgument(String val, String dt) 
	{
		this.value = val;
		this.dataType = dt;
	}
	@Override
	public String value() 
	{
		return this.value;
	}

	@Override
	public String dataType() 
	{
		return this.dataType;
	}
	
	@Override 
	public String toString() 
	{
		return this.value + "::" + this.dataType;
	}

}

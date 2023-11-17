package noCallsBefore;

public class VariableArgument implements Argument 
{
	private String value;
	private String dataType;
	
	public VariableArgument(String val, String type) 
	{
		value = val;
		dataType = type;
	}
	
	@Override
	public String value() 
	{
		return value;
	}

	@Override
	public String dataType() 
	{
		return dataType;
	}
	
	@Override
	public String toString() 
	{
		return this.value + "::" + this.dataType;
	}

}

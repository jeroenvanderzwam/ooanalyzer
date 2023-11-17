package noCallsBefore;

public class ConstantArgument implements Argument
{
	private String value;
	private String dataType;
	
	public ConstantArgument(String val, String type) 
	{
		value = val;
		dataType = type;
	}
	
	@Override
	public String value() {
		return value;
	}

	@Override
	public String dataType() {
		return dataType;
	}

}

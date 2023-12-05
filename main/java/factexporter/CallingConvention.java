package factexporter;

import java.util.List;

public class CallingConvention 
{
	private List<String> _preferredParameterLocation;
	private String _name;
	
	public CallingConvention(String name, List<String> preferredParameterLocation) 
	{
		_name = name;
		_preferredParameterLocation = preferredParameterLocation;
	}
	
	public String name() 
	{
		return _name;
	}
	
	public List<String> preferredParameterLocation() 
	{
		return _preferredParameterLocation;
	}

}

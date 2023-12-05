package factexporter;

import java.util.List;

public class CallingConvention 
{
	private List<String> _preferredParameterLocation;
	
	public CallingConvention(List<String> preferredParameterLocation) 
	{
		_preferredParameterLocation = preferredParameterLocation;
	}
	
	public List<String> preferredParameterLocation() 
	{
		return _preferredParameterLocation;
	}

}

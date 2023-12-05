package factexporter;

import java.util.List;

public class Function 
{
	private boolean _isThunk;
	private List<Parameter> _parameters;
	private String _address;
	private String _name;
	private CallingConvention _callingConvention;
	
	Function(String address, String name, boolean isThunk, List<Parameter> parameters, CallingConvention callingConv) 
	{
		_isThunk = isThunk;
		_parameters = parameters;
		_address = address.replaceFirst("00","0x");
		_name = name;
		_callingConvention = callingConv;
	}
	
	public String name() 
	{
		return _name;
	}
	
	public String address() 
	{
		return _address;
	}
	
	public boolean isThunk()
	{
		return _isThunk;
	}
	
	public List<Parameter> parameters()
	{
		return _parameters;
	}
	
	public boolean hasParameters() {
		return _parameters.size() != 0;
	}
}

package sourcecode;

import java.util.List;

import factexporter.CallingConvention;

public class Function 
{
	private final boolean _isThunk;
	private final List<Parameter> _parameters;
	private final String _address;
	private final String _name;
	private final CallingConvention _callingConvention;
	
	private List<Instruction> _instructions = null;
	
	public Function(String address, String name, boolean isThunk, List<Parameter> parameters, CallingConvention callingConv) 
	{
		_isThunk = isThunk;
		_parameters = parameters;
		_address = address.replaceFirst("00","0x");
		_name = name;
		_callingConvention = callingConv;
	}
	
	public Function(String address, String name, boolean isThunk, List<Parameter> parameters, CallingConvention callingConv,
			List<Instruction> instructions) 
	{
		this(address, name, isThunk, parameters, callingConv);
		_instructions = instructions;
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
	
	public CallingConvention callingConvention() 
	{
		return _callingConvention;
	}
	
	public List<Instruction> instructions()
	{
		return _instructions;
	}
	
	@Override
	public String toString() 
	{
		return _name;
	}
}

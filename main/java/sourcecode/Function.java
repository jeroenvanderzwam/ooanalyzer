package sourcecode;

import java.util.List;

import factexporter.CallingConvention;

public class Function 
{
	private final boolean isThunk;
	private final List<Parameter> parameters;
	private final String address;
	private final String name;
	private final CallingConvention callingConvention;
	
	private List<Instruction> instructions = null;
	
	public Function(String addr, String name, boolean isThunk, List<Parameter> parameters, CallingConvention callingConv) 
	{
		this.isThunk = isThunk;
		this.parameters = parameters;
		address = addr.replaceFirst("00","0x");
		this.name = name;
		callingConvention = callingConv;
	}
	
	public Function(String address, String name, boolean isThunk, List<Parameter> parameters, CallingConvention callingConv,
			List<Instruction> instructions) 
	{
		this(address, name, isThunk, parameters, callingConv);
		this.instructions = instructions;
	}
	
	public String name() 
	{
		return name;
	}
	
	public String address() 
	{
		return address;
	}
	
	public boolean isThunk()
	{
		return isThunk;
	}
	
	public List<Parameter> parameters()
	{
		return parameters;
	}
	
	public boolean hasParameters() {
		return parameters.size() != 0;
	}
	
	public CallingConvention callingConvention() 
	{
		return callingConvention;
	}
	
	public List<Instruction> instructions()
	{
		return instructions;
	}
	
	@Override
	public String toString() 
	{
		return name;
	}
}

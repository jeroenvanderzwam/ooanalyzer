package sourcecode;

import java.util.List;

import factexporter.CallingConvention;

public abstract class Func 
{
	private final List<Parameter> parameters;
	private final String address;
	private final String name;
	private final CallingConvention callingConvention;
	
	private List<Instruction> instructions = null;
	
	public Func(String addr, String name, List<Parameter> parameters, CallingConvention callingConv) 
	{
		this.parameters = parameters;
		address = addr;
		this.name = name;
		callingConvention = callingConv;
	}
	
	public Func(String address, String name, List<Parameter> parameters, CallingConvention callingConv,
			List<Instruction> instructions) 
	{
		this(address, name, parameters, callingConv);
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
	
	public abstract boolean isThunk();
}

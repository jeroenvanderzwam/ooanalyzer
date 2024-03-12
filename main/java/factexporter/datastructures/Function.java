package factexporter.datastructures;

import java.util.List;

public class Function 
{
	private List<Value> parameters;
	private String address;
	private String name;
	private CallingConvention callingConvention;
	private List<FunctionCallInstruction> functionCallInstructions = null;
	private boolean isThunk;
	
	public Function(String address, String name, List<Value> parameters, CallingConvention callingConv,
			List<FunctionCallInstruction> instructions, boolean isThunk) 
	{
		this.parameters = parameters;
		this.address = address;
		this.name = name;
		this.isThunk = isThunk;
		this.callingConvention = callingConv;
		this.functionCallInstructions = instructions;
	}

	public static Function createThunkFunction(String address, String name, List<Value> parameters, CallingConvention callingConv,
			List<FunctionCallInstruction> instructions) {
		return new Function(address, name, parameters, callingConv, instructions, true);
	}
	
	public static Function createFunction(String address, String name, List<Value> parameters, CallingConvention callingConv,
			List<FunctionCallInstruction> instructions) {
		return new Function(address, name, parameters, callingConv, instructions, false);
	}
	
	public String getName() 
	{
		return name;
	}
	
	public String getAddress() 
	{
		return address;
	}
	
	public List<Value> getParameters()
	{
		return parameters;
	}
	
	public boolean hasParameters() {
		return parameters.size() != 0;
	}
	
	public CallingConvention getCallingConvention() 
	{
		return callingConvention;
	}
	
	public List<FunctionCallInstruction> getInstructions()
	{
		return functionCallInstructions;
	}
	
	@Override
	public String toString() 
	{
		return name;
	}
	
	public boolean isThunk() 
	{
		return isThunk;
	}
}

package factexporter.datastructures;

import java.util.List;

public class FunctionCallInstruction
{
	private String instructionAddress;
	private List<Value> arguments;
	private Value output;
	private String functionAddress;
	
	public FunctionCallInstruction(String instructionAddr, String funcAddress, List<Value> args, Value out) 
	{
		instructionAddress = instructionAddr;
		functionAddress = funcAddress;
		arguments = args;
		output = out;
	}
	
	public String getAddress() {
		return instructionAddress;
	}
	
	public String getFunctionAddress() {
		return functionAddress;
	}
	
	public List<Value> getArguments() {
		return arguments;
	}
	
	public Value getOutput() {
		return output;
	}

}

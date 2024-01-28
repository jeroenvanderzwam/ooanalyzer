package factexporter.datastructures;

import java.util.List;

public class FunctionCallInstruction extends Instruction
{

	public FunctionCallInstruction(String address, List<Value> inputs, Value output) 
	{
		super(address, inputs, output);
	}

}

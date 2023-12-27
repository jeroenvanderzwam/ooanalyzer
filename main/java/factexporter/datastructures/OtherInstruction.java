package factexporter.datastructures;

import java.util.List;

public class OtherInstruction extends Instruction
{
	private final String memonic;
	protected final List<Value> inputs;
	protected final Value output;
	
	public OtherInstruction(String mnemonic, List<Value> inputs, Value output) 
	{
		memonic = mnemonic;
		this.inputs = inputs;
		this.output = output;
	}
	
	public String mnemonic() 
	{
		return memonic;
	}
	
	public List<Value> inputs() 
	{
		return inputs;
	}
	
	public Value output() 
	{
		return output;
	}
	
	@Override
	public String toString()
	{
		return "%s::%s::%s".formatted(memonic, inputs, output);
	}

	@Override
	public String name() {
		return memonic;
	}
}

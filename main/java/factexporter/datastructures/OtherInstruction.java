package factexporter.datastructures;

import java.util.List;

public class OtherInstruction extends Instruction
{
	private final String memonic;
	
	public OtherInstruction(String address, String mnemonic, List<Value> inputs, Value output) 
	{
		super(address, inputs, output);
		memonic = mnemonic;

	}
	
	public String mnemonic() 
	{
		return memonic;
	}
}

package sourcecode;

import java.util.List;

public class OtherInstruction extends Instruction
{
	private final String _memonic;
	protected final List<Value> _inputs;
	protected final Value _output;
	
	public OtherInstruction(String mnemonic, List<Value> inputs, Value output) 
	{
		_memonic = mnemonic;
		_inputs = inputs;
		_output = output;
	}
	
	public String mnemonic() 
	{
		return _memonic;
	}
	
	public List<Value> inputs() 
	{
		return _inputs;
	}
	
	public Value output() 
	{
		return _output;
	}
	
	@Override
	public String toString()
	{
		return "%s::%s::%s".formatted(_memonic, _inputs, _output);
	}
}

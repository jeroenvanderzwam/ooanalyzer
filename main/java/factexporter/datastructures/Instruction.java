package factexporter.datastructures;

import java.util.List;

public abstract class Instruction 
{
	private String address;
	private List<Value> inputs;
	private Value output;
	
	Instruction(String addr, List<Value> inps, Value out) 
	{
		address = addr;
		inputs = inps;
		output = out;
	}
	
	public String address() {
		return address;
	}
	
	public List<Value> inputs() {
		return inputs;
	}
	
	public Value output() {
		return output;
	}
}

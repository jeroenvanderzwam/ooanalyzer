package factexporter.datastructures;

import java.util.ArrayList;
import java.util.List;

public class FunctionCall extends Instruction
{
	private final String name;
	private final List<Value> params;
	
	private Value _returnValue;
	
	public FunctionCall(String name, List<Value> params, Value returnValue) 
	{
		this(name, params);
		_returnValue = returnValue;
	}
	
	public FunctionCall(String name, List<Value> params) 
	{
		this.name = name;
		this.params = params;
		_returnValue = null;
	}
	
	public String name() 
	{
		return name;
	}
	
	@Override
	public String toString()
	{
		ArrayList<String> strInputs = new ArrayList<String>();
		for(var input : params)
		{
			strInputs.add(input.toString());
		}
		return "%s(%s) --> %s".formatted(name, String.join(", ", strInputs), 
									     _returnValue != null ? _returnValue.toString() : "void");
	}

}

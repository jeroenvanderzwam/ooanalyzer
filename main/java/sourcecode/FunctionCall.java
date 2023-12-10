package sourcecode;

import java.util.ArrayList;
import java.util.List;

public class FunctionCall extends Instruction
{
	private final String _name;
	private final List<Value> _params;
	
	private Value _returnValue;
	
	public FunctionCall(String name, List<Value> params, Value returnValue) 
	{
		this(name, params);
		_returnValue = returnValue;
	}
	
	public FunctionCall(String name, List<Value> params) 
	{
		_name = name;
		_params = params;
		_returnValue = null;
	}
	
	public String name() 
	{
		return _name;
	}
	
	@Override
	public String toString()
	{
		ArrayList<String> strInputs = new ArrayList<String>();
		for(var input : _params)
		{
			strInputs.add(input.toString());
		}
		return "%s(%s) --> %s".formatted(_name, String.join(", ", strInputs), 
									     _returnValue != null ? _returnValue.toString() : "void");
	}

}

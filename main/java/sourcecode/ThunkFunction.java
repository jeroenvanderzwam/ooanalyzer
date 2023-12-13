package sourcecode;

import java.util.List;

import factexporter.CallingConvention;

public class ThunkFunction extends Func
{

	public ThunkFunction(String address, String name, List<Parameter> parameters, CallingConvention callingConv) 
	{
		super(address, name, parameters, callingConv);
		// TODO Auto-generated constructor stub
	}

	public ThunkFunction(String address, String name, List<Parameter> parameters, CallingConvention callingConv,
			List<Instruction> instructions) 
	{
		super(address, name, parameters, callingConv, instructions);
	}
	
	@Override
	public boolean isThunk() 
	{
		return true;
	}

}

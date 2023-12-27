package factexporter.datastructures;

import java.util.List;

public class Function extends Func
{

	public Function(String addr, String name, List<Parameter> parameters, CallingConvention callingConv) 
	{
		super(addr, name, parameters, callingConv);
	}
	
	public Function(String address, String name, List<Parameter> parameters, CallingConvention callingConv,
			List<Instruction> instructions) 
	{
		super(address, name, parameters, callingConv, instructions);
	}

	@Override
	public boolean isThunk() 
	{
		return false;
	}

}

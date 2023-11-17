package noCallsBefore;

import ghidra.program.model.pcode.HighConstant;
import ghidra.program.model.pcode.HighGlobal;
import ghidra.program.model.pcode.HighLocal;
import ghidra.program.model.pcode.HighOther;
import ghidra.program.model.pcode.HighVariable;

public class ConvertVariable 
{
	private HighVariable variable;
	
	public ConvertVariable(HighVariable var) 
	{
		variable = var;
	}
	
	public Argument resolve()
	{
		if (variable instanceof HighLocal) 
		{
			return new VariableArgument(value(), dataType());
		}
		else if (variable instanceof HighConstant)
		{
			return new ConstantArgument(value(), dataType());
		}
		return new UnknownArgument(value(), dataType());
	}
	
	public String value() 
	{
		String argumentValue = "";
		if (variable instanceof HighConstant) {
			var constant = (HighConstant)variable;
			argumentValue = constant.getScalar().toString();
		} else if(variable instanceof HighOther) {
			var highOther = (HighOther)variable;
			argumentValue = highOther.getName();
		} else if (variable instanceof HighLocal) {
			var highLocal = (HighLocal)variable;
			argumentValue = highLocal.getSymbol().getName();
		} else if (variable instanceof HighGlobal){
			var highGlobal = (HighGlobal)variable;
			argumentValue = highGlobal.getName();
		}
		return argumentValue;
	}
	
	private String dataType() {
		return variable.getDataType().toString();
	}
}

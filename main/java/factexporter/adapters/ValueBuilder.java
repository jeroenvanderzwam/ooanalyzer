package factexporter.adapters;

import factexporter.datastructures.Constant;
import factexporter.datastructures.OtherValue;
import factexporter.datastructures.Value;
import factexporter.datastructures.Variable;
import ghidra.program.model.pcode.HighConstant;
import ghidra.program.model.pcode.HighGlobal;
import ghidra.program.model.pcode.HighLocal;
import ghidra.program.model.pcode.HighOther;
import ghidra.program.model.pcode.Varnode;

public class ValueBuilder 
{
	ValueBuilder()
	{
		
	}
	
	Value build(Varnode output)
	{
		var variable = output.getHigh();
		if (variable instanceof HighConstant) {
			var constant = (HighConstant)variable;
			return new Constant(constant.getScalar().toString(), constant.getSize());
		} else if(variable instanceof HighOther) {
			var highOther = (HighOther)variable;
			return new Variable(highOther.getName(), highOther.getSize());
		} else if (variable instanceof HighLocal) {
			var highLocal = (HighLocal)variable;
			return new Variable(highLocal.getSymbol().getName(), highLocal.getSize());
		} else if (variable instanceof HighGlobal){
			var highGlobal = (HighGlobal)variable;
			return new Variable(highGlobal.getName(), highGlobal.getSize());
		} else {
			return new OtherValue(0);
		}
	}
}

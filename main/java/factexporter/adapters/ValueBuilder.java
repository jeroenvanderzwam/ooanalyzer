package factexporter.adapters;

import factexporter.datastructures.Constant;
import factexporter.datastructures.OtherValue;
import factexporter.datastructures.Register;
import factexporter.datastructures.Stack;
import factexporter.datastructures.Storage;
import factexporter.datastructures.Value;
import factexporter.datastructures.Variable;
import ghidra.program.model.pcode.HighConstant;
import ghidra.program.model.pcode.HighGlobal;
import ghidra.program.model.pcode.HighLocal;
import ghidra.program.model.pcode.HighOther;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.Varnode;

class ValueBuilder 
{
	ValueBuilder() {}
	
	Value build(Varnode output)
	{
		var variable = output.getHigh();
		Storage store = null; 
		if (variable != null) {
			var symbol =  variable.getSymbol();
			
			var storage = symbol != null ? symbol.getStorage() : null;
			if (storage != null) {
				if (storage.isRegisterStorage()) {
					store = new Register(storage.getRegister().getName());
				} else {
					store = new Stack();
				}
			}
		}
		
		if (variable instanceof HighConstant) {
			var constant = (HighConstant)variable;
			var name = constant.getSymbol() != null ? constant.getSymbol().getName() : "Unknown";
			return new Constant(name, constant.getScalar().toString(), constant.getSize(), store );
		} else if(variable instanceof HighOther) {
			var highOther = (HighOther)variable;
			return new Variable(highOther.getName(), "", highOther.getSize(), store);
		} else if (variable instanceof HighLocal) {
			var highLocal = (HighLocal)variable;
			return new Variable(highLocal.getSymbol().getName(),"", highLocal.getSize(), store);
		} else if (variable instanceof HighGlobal){
			var highGlobal = (HighGlobal)variable;
			return new Variable(highGlobal.getName(),"", highGlobal.getSize(), store);
		} else {
			return new OtherValue();
		}
	}
}

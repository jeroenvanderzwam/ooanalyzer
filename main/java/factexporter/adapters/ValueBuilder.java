package factexporter.adapters;

import factexporter.datastructures.Storage;
import factexporter.datastructures.Value;
import ghidra.program.model.pcode.HighConstant;
import ghidra.program.model.pcode.HighGlobal;
import ghidra.program.model.pcode.HighLocal;
import ghidra.program.model.pcode.HighOther;
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
					store = Storage.createRegister(storage.getRegister().getName());
				} else if (storage.hasStackStorage() ) {
					store = Storage.createStack(storage.getStackOffset());
				}
			}
		}
		
		if (variable instanceof HighConstant) {
			var constant = (HighConstant)variable;
			var name = constant.getSymbol() != null ? constant.getSymbol().getName() : "Unknown";
			return Value.createConstant(name, constant.getScalar().toString(), constant.getSize(), store );
		} else if(variable instanceof HighOther) {
			var highOther = (HighOther)variable;
			return Value.createVariable(highOther.getName(), highOther.getSize(), store);
		} else if (variable instanceof HighLocal) {
			var highLocal = (HighLocal)variable;
			return Value.createVariable(highLocal.getSymbol().getName(), highLocal.getSize(), store);
		} else if (variable instanceof HighGlobal){
			var highGlobal = (HighGlobal)variable;
			return Value.createVariable(highGlobal.getName(), highGlobal.getSize(), store);
		} else {
			return Value.createOtherValue();
		}
	}
}

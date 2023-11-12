package factexporter;

import java.util.ArrayList;
import java.util.List;

import org.javatuples.Triplet;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighConstant;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighGlobal;
import ghidra.program.model.pcode.HighLocal;
import ghidra.program.model.pcode.HighOther;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.Msg;

public class ThisPtrCalls 
{
	private List<Triplet<Function, Function, ArgumentValue>> functionCalls = new ArrayList<Triplet<Function, Function, ArgumentValue>>();
	private Program _program;
	
	public ThisPtrCalls(Program program) 
	{
		_program = program;
	}
	
	class ArgumentValue {
		private String name;
		private String type;
		
		public ArgumentValue(String name, String type) 
		{
			this.name = name;
			this.type = type;
		}
		
		@Override
		public String toString() 
		{
			return this.name + "::" + this.type;
		}
	}
	

	private String argumentValue(HighVariable highVariable) {
		String argumentValue = "";
		if (highVariable instanceof HighConstant) {
			var constant = (HighConstant)highVariable;
			argumentValue = constant.getScalar().toString();
		} else if(highVariable instanceof HighOther) {
			var highOther = (HighOther)highVariable;
			argumentValue = highOther.getName();
		} else if (highVariable instanceof HighLocal) {
			var highLocal = (HighLocal)highVariable;
			argumentValue = highLocal.getSymbol().getName();
		} else if (highVariable instanceof HighGlobal){
			var highGlobal = (HighGlobal)highVariable;
			argumentValue = highGlobal.getName();
		}
		return argumentValue;
	}
	
	private String argumentDataType(HighVariable highVariable) {
		return highVariable.getDataType().toString();
	}

	public void run() 
	{
		
		var funcIter = _program.getListing().getFunctions(true);
		DecompInterface decompInterface = new DecompInterface();
		decompInterface.openProgram(_program);
		while (funcIter.hasNext())
		{
			var function = funcIter.next();

			DecompileResults results = decompInterface.decompileFunction(function, 0, null);
			HighFunction highFunction = results.getHighFunction();
			var pCodeOps = highFunction.getPcodeOps();
			while (pCodeOps.hasNext()) 
			{
				var op = pCodeOps.next();
				var opCode = op.getOpcode();
				if (opCode == PcodeOp.CALL ) {

					handleCalls(function, op.getInputs());
				} 
				else if (opCode == PcodeOp.CALLIND) 
				{
					handleIndirectCalls(function, op.getInputs());
				}
			}
		}
		Msg.out("Found " + functionCalls.size() + " tuples.");
		for(var functionCall : functionCalls)
		{
			Msg.out(String.format("%s, %s, %s, %s", 
					functionCall.getValue0().getName(), 
					functionCall.getValue0().getEntryPoint(), 
					functionCall.getValue1().getName(), 
					functionCall.getValue2()));
		}
	}

	private void handleIndirectCalls(Function function, Varnode[] inputs) {
		Msg.out(inputs);
	}

	private void handleCalls(Function function, Varnode[] inputs) {

		var funcAddress = inputs[0].getAddress();
		var calledFunction = _program.getListing().getFunctionAt(funcAddress);
		if (calledFunction != null) {
			if (inputs.length >= 2) {
				var arg1 = inputs[1].getHigh();
				String name = argumentValue(arg1);
				String dataType = argumentDataType(arg1);
				functionCalls.add(new Triplet<Function, Function, ArgumentValue>(function, 
						calledFunction, 
						new ArgumentValue(name, dataType)));
			}
		}
		
	}
}

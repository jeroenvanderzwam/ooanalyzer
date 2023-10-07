package factexporter;

import java.util.ArrayList;
import java.util.List;

import org.javatuples.Triplet;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.FunctionPrototype;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.symbol.RefType;
import ghidra.util.Msg;

public class ThisPtrCalls {

	public void run(Program program) 
	{
		List<Triplet<Function, Function, Boolean>> functionCalls = new ArrayList<Triplet<Function, Function, Boolean>>();
		var funcIter = program.getListing().getFunctions(true);
		DecompInterface decompInterface = new DecompInterface();
		decompInterface.openProgram(program);
		while (funcIter.hasNext())
		{
			var function = funcIter.next();
			var functionBodyAddresses = function.getBody().getAddresses(true);
			for (var address : functionBodyAddresses)
			{
				var ins = program.getListing().getInstructionAt(address);
				if (ins != null && ins.getFlowType() == RefType.UNCONDITIONAL_CALL)
				{
					var funcAddress = ins.getFlows()[0];
					var calledFunction = program.getListing().getFunctionAt(funcAddress);
					Boolean firstParameterIsThis = false;
					if (calledFunction.getParameterCount() > 0) {
						DecompileResults res = decompInterface.decompileFunction(calledFunction, 30, null);
						HighFunction highFunction = res.getHighFunction();
						FunctionPrototype funcPrototype = highFunction.getFunctionPrototype();
						HighSymbol firstParamaterSymbol = funcPrototype.getParam(0);
						firstParameterIsThis = firstParamaterSymbol.isThisPointer();
					}
					var triplet = new Triplet<Function, Function, Boolean>(function, calledFunction, firstParameterIsThis);
					functionCalls.add(triplet);
				}
			}
			
		}
		for(var functionCall : functionCalls)
		{
			Msg.out(String.format("%s: %s: %s", functionCall.getValue0(), functionCall.getValue1(), functionCall.getValue2()));
		}
	}
}

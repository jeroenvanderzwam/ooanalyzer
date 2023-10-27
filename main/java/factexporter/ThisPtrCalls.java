package factexporter;

import java.util.ArrayList;
import java.util.List;

import org.javatuples.Triplet;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.data.Undefined4DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.FunctionPrototype;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.VarnodeAST;
import ghidra.program.model.symbol.RefType;
import ghidra.util.Msg;

public class ThisPtrCalls {
	
	class ECXValue {
		private String name;
		private String type;
		
		public ECXValue(String name, String type) {
			this.name = name;
			this.type = type;
		}
		
		@Override
		public String toString() {
			return this.name + "::" + this.type;
		}
	}

	public void run(Program program) 
	{
		List<Triplet<Function, Function, ECXValue>> functionCalls = new ArrayList<Triplet<Function, Function, ECXValue>>();
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
					if (calledFunction.getName().equals("__RTC_CheckEsp")) { continue;}
					
					ECXValue ecxValue = null;
					if (calledFunction.getParameterCount() > 0) {
						DecompileResults res = decompInterface.decompileFunction(calledFunction, 30, null);
						HighFunction highFunction = res.getHighFunction();
						FunctionPrototype funcPrototype = highFunction.getFunctionPrototype();
						HighSymbol firstParamaterSymbol = funcPrototype.getParam(0);
						HighVariable firstParamaterVariable = firstParamaterSymbol.getHighVariable();
						VarnodeAST firstParameterVarnode = (VarnodeAST)firstParamaterVariable.getRepresentative();
						if (firstParameterVarnode.isRegister()) {
							var register = program.getRegister(firstParameterVarnode.getAddress());
							var name = register.getName();
							if (name.equals("ECX")) {
								if (firstParamaterSymbol.getDataType() instanceof PointerDataType ||
									firstParamaterSymbol.getDataType() instanceof Undefined4DataType) {
									ecxValue = new ECXValue(firstParamaterSymbol.getName(), firstParamaterSymbol.getDataType().getName());
									var triplet = new Triplet<Function, Function, ECXValue>(function, calledFunction, ecxValue);
									functionCalls.add(triplet);
								} else {
									Msg.out("");
								}

							}
							
						}
					}

				}
			}
		}
		Msg.out(functionCalls.size());
		for(var functionCall : functionCalls)
		{
			Msg.out(String.format("%s: %s: %s", functionCall.getValue0(), functionCall.getValue1(), functionCall.getValue2()));
		}
	}
}

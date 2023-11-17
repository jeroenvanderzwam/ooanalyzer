package noCallsBefore;

import java.util.ArrayList;
import java.util.List;

import org.javatuples.Triplet;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.Msg;

public class ThisPtrCalls 
{
	private List<Triplet<Function, Function, Argument>> functionCalls = new ArrayList<Triplet<Function, Function, Argument>>();
	private Program _program;
	
	public ThisPtrCalls(Program program) 
	{
		_program = program;
	}
	
	public void run() 
	{
		var funcIter = _program.getListing().getFunctions(true);
		DecompInterface decompInterface = new DecompInterface();
		decompInterface.openProgram(_program);
		while (funcIter.hasNext())
		{
			var function = funcIter.next();
			var ecx = _program.getLanguage().getRegister("ECX");
			var callerDecomp = decompInterface.decompileFunction(function, 0, null);
			var highFunction = callerDecomp.getHighFunction();
			var pCodeOps = highFunction.getPcodeOps();
			while (pCodeOps.hasNext()) 
			{
				var op = pCodeOps.next();
				
				var inputs = op.getInputs();
				var funcAddress = inputs[0].getAddress();
				var calledFunction = _program.getListing().getFunctionAt(funcAddress);
				
				var opCode = op.getOpcode();
				if (opCode == PcodeOp.CALL) 
				{
					if (calledFunction == null) { continue; }
					var calleeDecomp = decompInterface.decompileFunction(calledFunction, 0, null);
					var funcPrototype = calleeDecomp.getHighFunction().getFunctionPrototype();
					if (funcPrototype.getNumParams() < 1) { continue;}
					
					var param = funcPrototype.getParam(0);
					var registers = param.getStorage().getRegisters();
					if (registers != null && registers.contains(ecx)) {
						var arg1 = inputs[1];

						var highVariable = arg1.getHigh();
						functionCalls.add(new Triplet<Function, Function, Argument>(function, calledFunction, new ConvertVariable(highVariable).resolve()));
					}

				} 
				else if (opCode == PcodeOp.CALLIND) 
				{
					if (inputs.length < 2) {continue;}
					var arg1 = inputs[1];
					if (arg1.isRegister()) {
						Msg.out(String.format("%s %s", funcAddress, arg1.getHigh().getName()));
					}
				}
			}
		}
		
		printFunctionCalls();
	}
	
	private void printFunctionCalls() {
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

}

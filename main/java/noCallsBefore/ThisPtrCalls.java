package noCallsBefore;

import java.util.ArrayList;
import java.util.List;

import org.javatuples.Triplet;

import factexporter.DecompilationService;
import ghidra.util.Msg;
import sourcecode.Function;
import sourcecode.FunctionCall;
import sourcecode.Value;
import thispointer.ThisPointer;

public class ThisPtrCalls 
{
	private List<Triplet<Function, String, Value>> functionCalls = new ArrayList<Triplet<Function, String, Value>>();
	private DecompilationService _decompService;
	
	public ThisPtrCalls(DecompilationService decompService) 
	{
		_decompService = decompService;
	}
	
	public void run() 
	{
		var compilerSpec = _decompService.compilerSpec();
		var thisPointerRegister = new ThisPointer().build(compilerSpec);
		for (var function : _decompService.functions())
		{
			for (var instruction : function.instructions()) 
			{
				if (instruction instanceof FunctionCall) 
				{
					var functionCall = (FunctionCall)instruction;
					if (function.parameters().size() < 1) { continue;}
					var firstParam = function.parameters().get(0);
					if (firstParam.inRegister() && firstParam.register().name().equals(thisPointerRegister.name())) {
						functionCalls.add(new Triplet<Function, String, Value>(function, functionCall.name(), function.parameters().get(0)));
					}
				} 
				else //if (opCode == PcodeOp.CALLIND) 
				{
//					if (inputs.length < 1) {continue;}
//					var high = inputs[0].getHigh();
//					Msg.out(String.format("%s %s %s",function.getName(), callAddress, high));
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
					functionCall.getValue0().name(), 
					functionCall.getValue0().address(), 
					functionCall.getValue1(), 
					functionCall.getValue2()));
		}
	}

}

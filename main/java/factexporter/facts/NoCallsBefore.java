package factexporter.facts;

import java.util.ArrayList;
import java.util.List;

import org.javatuples.Triplet;

import factexporter.DecompilationService;
import factexporter.datastructures.Func;
import factexporter.datastructures.FunctionCallInstruction;
import factexporter.datastructures.Value;
import factexporter.export.File;
import ghidra.util.Msg;

class NoCallsBefore implements Fact 
{
	private DecompilationService decompService;
	
	public NoCallsBefore(DecompilationService service) 
	{
		decompService = service;
	}

	public void createFacts(File file) 
	{
		var functionCalls = new ArrayList<Triplet<Func, String, Value>>();
		var compilerSpec = decompService.compilerSpec();
		var thisPointerRegister = new ThisPointer().build(compilerSpec);
		for (var function : decompService.functions())
		{
			for (var instruction : function.instructions()) 
			{
				if (instruction instanceof FunctionCallInstruction) 
				{
					var functionCall = (FunctionCallInstruction)instruction;
					if (function.parameters().size() < 1) { continue;}
					var firstParam = function.parameters().get(0);
					if (firstParam.inRegister() && firstParam.storage().name().equals(thisPointerRegister.name())) {
						functionCalls.add(new Triplet<Func, String, Value>(function, functionCall.inputs().get(0).name(), function.parameters().get(0)));
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
		
		printFunctionCalls(functionCalls);
	}
	
	private void printFunctionCalls(List<Triplet<Func, String, Value>> functionCalls) {
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

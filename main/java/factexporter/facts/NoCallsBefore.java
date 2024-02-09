package factexporter.facts;

import java.util.ArrayList;
import java.util.List;

import org.javatuples.Triplet;

import factexporter.DecompilationService;
import factexporter.datastructures.Function;
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
		var functionCalls = new ArrayList<Triplet<Function, String, Value>>();
		var compilerSpec = decompService.compilerSpec();
		var thisPointerRegister = new ThisPointer().build(compilerSpec);
		for (var function : decompService.functions())
		{
			for (var instruction : function.instructions()) 
			{
				if (function.getParameters().size() < 1) { continue;}
				var firstParam = function.getParameters().get(0);
				if (firstParam.inRegister() && firstParam.getStorage().getName().equals(thisPointerRegister.name())) {
					//functionCalls.add(new Triplet<Function, String, Value>(function, functionCall.inputs().get(0).name(), function.parameters().get(0)));
				}
			}
		}
		
		printFunctionCalls(functionCalls);
	}
	
	private void printFunctionCalls(List<Triplet<Function, String, Value>> functionCalls) {
		Msg.out("Found " + functionCalls.size() + " tuples.");
		for(var functionCall : functionCalls)
		{
			Msg.out(String.format("%s, %s, %s, %s", 
					functionCall.getValue0().name(), 
					functionCall.getValue0().getAddress(), 
					functionCall.getValue1(), 
					functionCall.getValue2()));
		}
	}
}

package factexporter.facts;

import factexporter.DataFlowGraphService;
import factexporter.DecompilationService;
import factexporter.datastructures.Function;
import factexporter.export.File;
import factexporter.facts.ThisPointer.ThisPointerRegister;

class ReturnsSelf implements Fact 
{
	private final DecompilationService dataService;
	private final DataFlowGraphService graphService;
	private final ThisPointerRegister thisPointerRegister;
	
	public ReturnsSelf(DecompilationService dataServ, DataFlowGraphService graphServ)
	{
		dataService = dataServ;
		graphService = graphServ;
		var compilerSpec = dataService.compilerSpec();
		thisPointerRegister = new ThisPointer().build(compilerSpec);
	}

	public void createFacts(File file) {
		for (var function : dataService.functions())
		{
			if (functionReturnsSelf(function)) {
				var output = String.format("returnsSelf(%s).", function.getAddress());
				file.write(output);
			}
		}
	}
	
	private boolean functionReturnsSelf(Function function) {
		if (function.isThunk()) { return false; }
		if (!function.hasParameters()) { return false ;}
		if (firstParamHasPathToReturn(function)) {
			return true;
		}
		return false;
	}
	
	private boolean firstParamHasPathToReturn(Function function) {
		var firstParam = function.getParameters().get(0);
		if (firstParam.inRegister()) {
			if (firstParam.getStorage().getName().equals(thisPointerRegister.name())) {
				graphService.buildGraph(function);
				if (graphService.pathFromParamToReturn(firstParam)) {
					return true;
				}
			}
		}
		return false;
	}

}

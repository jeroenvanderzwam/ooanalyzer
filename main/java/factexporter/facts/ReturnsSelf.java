package factexporter.facts;

import factexporter.DataFlowGraphService;
import factexporter.DecompilationService;
import factexporter.datastructures.Func;
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
		file.open();
		for (var function : dataService.functions())
		{
			if (functionReturnsSelf(function)) {
				var output = String.format("returnsSelf(%s).", function.address());
				file.write(output);
			}
		}
		file.close();
	}
	
	private boolean functionReturnsSelf(Func function) {
		if (function.isThunk()) { return false; }
		if (!function.hasParameters()) { return false ;}
		if (firstParamHasPathToReturn(function)) {
			return true;
		}
		return false;
	}
	
	private boolean firstParamHasPathToReturn(Func function) {
		var firstParam = function.parameters().get(0);
		if (firstParam.inRegister()) {
			if (firstParam.register().name().equals(thisPointerRegister.name())) {
				graphService.buildGraph(function);
				if (graphService.pathFromParamToReturn(firstParam)) {
					return true;
				}
			}
		}
		return false;
	}

}

package returnsSelf;

import export.File;
import factexporter.DataFlowGraphService;
import factexporter.DecompilationService;
import facts.Fact;
import sourcecode.Func;
import thispointer.ThisPointer;
import thispointer.ThisPointer.ThisPointerRegister;

public class ReturnsSelf implements Fact 
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

	public void CreateFacts(File file) {
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
		var param = function.parameters().get(0);
		if (param.inRegister()) {
			if (param.register().name().equals(thisPointerRegister.name())) {
				graphService.buildGraph(function);
				if (graphService.pathFromParamToReturn(param)) {
					return true;
				}
			}
		}
		return false;
	}
}

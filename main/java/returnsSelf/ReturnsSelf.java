package returnsSelf;

import dataflow.DataFlowGraphService;
import export.File;
import factexporter.DecompilationService;
import facts.Fact;
import thispointer.ThisPointer;

public class ReturnsSelf implements Fact 
{
	private DecompilationService dataService;
	private DataFlowGraphService graphService;
	
	public ReturnsSelf(DecompilationService dataServ, DataFlowGraphService graphServ)
	{
		dataService = dataServ;
		graphService = graphServ;
	}

	public void CreateFacts(File file) {
		var compilerSpec = dataService.compilerSpec();
		file.open();
		var thisPointerRegister = new ThisPointer().build(compilerSpec);
		for (var function : dataService.functions())
		{
			if (function.isThunk()) { continue; }
			if (!function.hasParameters()) { continue ;}
			
			var param = function.parameters().get(0);
			if (param.inRegister()) {
				if (param.register().name().equals(thisPointerRegister.name())) {
					graphService.buildGraph(function);
					
					if (graphService.pathFromParamToReturn(param)) {
						var output = String.format("returnsSelf(%s).", function.address());
						file.write(output);
					}
				}
			}
		}
		file.close();
	}
}

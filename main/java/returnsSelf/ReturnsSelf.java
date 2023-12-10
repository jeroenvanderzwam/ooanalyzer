package returnsSelf;

import dataflow.DataFlowGraphService;
import export.File;
import factexporter.DecompilationService;
import facts.Fact;
import thispointer.ThisPointer;

public class ReturnsSelf implements Fact 
{
	private DecompilationService _dataService;
	private DataFlowGraphService _graphService;
	
	public ReturnsSelf(DecompilationService dataService, DataFlowGraphService graphService)
	{
		_dataService = dataService;
		_graphService = graphService;
	}

	public void CreateFacts(File file) {
		var compilerSpec = _dataService.compilerSpec();
		file.open();
		var thisPointerRegister = new ThisPointer().build(compilerSpec);
		for (var function : _dataService.functions())
		{
			if (function.isThunk()) { continue; }
			if (!function.hasParameters()) { continue ;}
			
			var param = function.parameters().get(0);
			if (param.inRegister()) {
				if (param.register().name().equals(thisPointerRegister.name())) {
					_graphService.buildGraph(function);
					
					if (_graphService.pathFromParamToReturn(param)) {
						var output = String.format("returnsSelf(%s).", function.address());
						file.write(output);
					}
				}
			}
		}
		file.close();
	}
}

package returnsSelf;

import java.util.regex.Pattern;

import factexporter.DataFlowGraphService;
import factexporter.DecompilationService;
import factexporter.Fact;
import factexporter.File;
import factexporter.TextFile;
import factexporter.ThisPointer;

public class ReturnsSelf implements Fact {

	public void CreateFacts(DecompilationService dataService, DataFlowGraphService graphService) {
		var compilerSpec = dataService.compilerSpec();
		var fileName = "C:/Users/jeroe/Downloads/Facts/Ghidra/" + dataService.decompiledFileName().split(Pattern.quote("."))[0] + ".ghidrafacts";
		File file = new TextFile(fileName);
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

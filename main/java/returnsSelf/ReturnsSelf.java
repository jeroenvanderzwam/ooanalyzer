package returnsSelf;

import java.util.regex.Pattern;

import factexporter.DecompilationService;
import factexporter.Fact;
import factexporter.File;
import factexporter.TextFile;

public class ReturnsSelf implements Fact {

	@Override
	public void CreateFacts(DecompilationService service) {
		var fileName = "C:/Users/jeroe/Downloads/Facts/Ghidra/" + service.decompiledFileName().split(Pattern.quote("."))[0] + ".ghidrafacts";
		File file = new TextFile(fileName);
		file.open();
		for (var function : service.functions())
		{
			if (function.isThunk()) { continue; }
			if (!function.hasParameters()) { continue ;}
			
			var param = function.parameters().get(0);
			if (param.inRegister()) {
				if (param.register().name().equals("ECX")) {
					service.buildGraph(function);
					
					if (service.pathFromParamToReturn(param)) {
						var output = String.format("returnsSelf(%s).", function.address());
						file.write(output);
					}
				}
			}
		}
		file.close();
	}
}

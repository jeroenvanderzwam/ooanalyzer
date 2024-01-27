package factexporter.facts;

import factexporter.DecompilationService;
import factexporter.export.File;

public class CallingConvention implements Fact {
	private DecompilationService decompilationService;
	
	public CallingConvention(DecompilationService decompService) {
		decompilationService = decompService;
	}

	@Override
	public void createFacts(File output) {
		var functions = decompilationService.functions();
		for (var function : functions) {
			var text = "callingConvention(%s, %s)".formatted(function.address(), function.callingConvention().name());
			output.write(text);
		}
	}

}

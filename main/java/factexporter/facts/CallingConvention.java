package factexporter.facts;

import factexporter.DecompilationService;
import factexporter.export.File;

class CallingConvention implements Fact {
	private DecompilationService decompilationService;
	
	public CallingConvention(DecompilationService decompService) {
		decompilationService = decompService;
	}

	@Override
	public void createFacts(File output) {
		var functions = decompilationService.functions();
		for (var function : functions) {
			var name = function.callingConvention().name();
			String text = "";
			if (name.equals("invalid")) {
				text = "callingConvention(%s, %s)".formatted(function.getAddress(), name);
			} else {
				text = "callingConvention(%s, '%s')".formatted(function.getAddress(), name);
			}
			output.write(text);
		}
	}

}

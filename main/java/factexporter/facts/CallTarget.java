package factexporter.facts;

import factexporter.DecompilationService;
import factexporter.datastructures.FunctionCallInstruction;
import factexporter.export.File;

class CallTarget implements Fact {
	private DecompilationService decompilationService;

	public CallTarget(DecompilationService decompService) {
		decompilationService = decompService;
	}

	@Override
	public void createFacts(File output) {
		for (var function : decompilationService.functions()) {
			for (var instruction : function.instructions()) {
				if (instruction instanceof FunctionCallInstruction) {
					//var text = "callTarget(%s,%s,%s)".formatted(, function.address(), instruction.name())
				}
			}
		}
	}

}

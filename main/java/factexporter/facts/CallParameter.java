package factexporter.facts;

import factexporter.DecompilationService;
import factexporter.datastructures.FunctionCallInstruction;
import factexporter.export.File;

class CallParameter implements Fact {
	
	private DecompilationService decompilationService;

	public CallParameter(DecompilationService decompService) {
		decompilationService = decompService;
	}
	
	@Override
	public void createFacts(File output) {
		var functions = decompilationService.functions();
		for (var function : functions) {
			for (var instruction : function.instructions()) {
				if (instruction instanceof FunctionCallInstruction) {
					for (var input : instruction.inputs()) {
						var text = "callParameter(%s, %s, %s, %s)".formatted(instruction.address(), function.address(), 
								input.storage() != null ? input.storage().name() : "", input.name());
						output.write(text);
					}

				}
			}
		}
	}

}

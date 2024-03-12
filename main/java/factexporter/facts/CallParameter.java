package factexporter.facts;

import factexporter.DecompilationService;
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
			for (var instruction : function.getInstructions()) {
				for (var arg : instruction.getArguments()) {
					var storage = arg.getStorage();
					if (storage != null) {
						var calledFunction = functions.stream().filter(p -> 
								p.getAddress().equals(instruction.getFunctionAddress())).findFirst();
						
						if (calledFunction.isPresent() && calledFunction.get().getParameters().size() == (instruction.getArguments().size())) {
							var parameter = calledFunction.get().getParameters().get(arg.getIndex());
							String position = "";
							if (parameter.inRegister()) {
								position = parameter.getStorage().getName();
							} else {
								position = Integer.toString(parameter.getStorage().getOffset() / 4);
							}
							var text = "callParameter(%s, %s, %s, %s)".formatted(
									instruction.getAddress(), function.getAddress(), position, arg.getName());
							output.write(text);
						} 
					}
				}
			}
		}
	}

}

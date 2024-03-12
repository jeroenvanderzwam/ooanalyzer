package factexporter.facts;

import factexporter.DecompilationService;
import factexporter.export.File;

public class InitialMemory implements Fact {
	
	private DecompilationService decompilationService;

	public InitialMemory(DecompilationService decompService) {
		this.decompilationService = decompService;
	}

	@Override
	public void createFacts(File output) {
		for(var memory : decompilationService.memory()) {
			var text = "initialMemory(%s, %s)".formatted(memory.address, memory.value);
			output.write(text);
		}
	}
}

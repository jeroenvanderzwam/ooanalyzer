package noCallsBefore;

import factexporter.DecompilationService;
import factexporter.Fact;
import ghidra.program.model.listing.Program;

public class NoCallsBefore implements Fact {

	@Override
	public void CreateFacts(DecompilationService service) {
		
		ThisPtrCalls thisPtrCalls = new ThisPtrCalls(null);
		thisPtrCalls.run();
	}


}

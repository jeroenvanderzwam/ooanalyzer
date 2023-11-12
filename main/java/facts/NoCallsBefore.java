package facts;

import factexporter.ThisPtrCalls;
import ghidra.program.model.listing.Program;

public class NoCallsBefore implements Fact {

	@Override
	public void CreateFacts(Program program) {
		ThisPtrCalls thisPtrCalls = new ThisPtrCalls(program);
		thisPtrCalls.run();
	}

}

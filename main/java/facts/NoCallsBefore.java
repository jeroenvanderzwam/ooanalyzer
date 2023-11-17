package facts;

import ghidra.program.model.listing.Program;
import noCallsBefore.ThisPtrCalls;

public class NoCallsBefore implements Fact {

	@Override
	public void CreateFacts(Program program) {
		ThisPtrCalls thisPtrCalls = new ThisPtrCalls(program);
		thisPtrCalls.run();
	}

}

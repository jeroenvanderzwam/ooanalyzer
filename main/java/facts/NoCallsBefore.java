package facts;

import factexporter.ControlFlow;
import ghidra.program.model.listing.Program;

public class NoCallsBefore implements Fact {

	@Override
	public void CreateFacts(Program program) {
		ControlFlow controlFlow = new ControlFlow();
		controlFlow.run(program);
	}

}

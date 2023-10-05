package facts;

import factexporter.ControlFlowV1;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.AcyclicCallGraphBuilder;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class NoCallsBefore implements Fact {

	@Override
	public void CreateFacts(Program program) {
		Function startingPoint = program.getListing().getGlobalFunctions("entry").get(0);
		ControlFlowV1 controlFlow = new ControlFlowV1();
		controlFlow.run(program);
	}

}

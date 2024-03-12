package factexporter.facts;

import factexporter.DataFlowGraphService;
import factexporter.DecompilationService;
import tests.FakeDecompilationService;

public class FactFactory 
{
	public Fact createReturnsSelf(DecompilationService decompServ, DataFlowGraphService dataFlowGraphServ) {
		return new ReturnsSelf(decompServ, dataFlowGraphServ);
	}
	
	public Fact createNoCallsBefore(DecompilationService decompServ) {
		return new NoCallsBefore(decompServ);
	}
	
	public Fact createCallingConvention(DecompilationService decompServ) {
		return new CallingConvention(decompServ);
	}

	public Fact createCallParameter(DecompilationService decompService) {
		return new CallParameter(decompService);
	}

	public Fact createCallTarget(DecompilationService decompService) {
		return new CallTarget(decompService);
	}

	public Fact createInitialMemory(DecompilationService decompService) {
		return new InitialMemory(decompService);
	}
}

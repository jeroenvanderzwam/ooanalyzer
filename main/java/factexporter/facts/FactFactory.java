package factexporter.facts;

import factexporter.DataFlowGraphService;
import factexporter.DecompilationService;

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
}

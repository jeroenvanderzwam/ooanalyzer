package factexporter;

import factexporter.facts.Fact;
import factexporter.facts.NoCallsBefore;
import factexporter.facts.ReturnsSelf;

public class FactFactory 
{
	public Fact createReturnsSelf(DecompilationService decompServ, DataFlowGraphService dataFlowGraphServ) {
		return new ReturnsSelf(decompServ, dataFlowGraphServ);
	}
	
	public Fact createNoCallsBefore(DecompilationService decompServ) {
		return new NoCallsBefore(decompServ);
	}
}

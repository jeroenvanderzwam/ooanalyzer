package factexporter;

import java.util.ArrayList;

import factexporter.export.File;
import factexporter.facts.Fact;
import factexporter.facts.FactFactory;

public class FactExporter {
	
	private DecompilationService decompService;
	private DataFlowGraphService dataFlowGraphService;
	
	public FactExporter(DecompilationService decompServ, DataFlowGraphService dataFlowGraphServ) 
	{
		decompService = decompServ;
		dataFlowGraphService = dataFlowGraphServ;
	}
	
	public void createFacts(File file) 
	{
		var factFactory = new FactFactory();
		var facts = new ArrayList<Fact>() 
		{{
			add(factFactory.createReturnsSelf(decompService, dataFlowGraphService));
			add(factFactory.createCallingConvention(decompService));
			//add(factFactory.createNoCallsBefore(decompService));
		}};
		
		file.open();
		for(Fact fact : facts) {
			fact.createFacts(file);
		}
		file.close();
	}
}

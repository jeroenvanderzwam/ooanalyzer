package factexporter;

import java.util.ArrayList;
import java.util.regex.Pattern;

import factexporter.export.File;
import factexporter.export.TextFile;
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
	
	public void createFacts() 
	{
		var fileName = "C:/Users/jeroe/Downloads/Facts/Ghidra/" + decompService.decompiledFileName().split(Pattern.quote("."))[0] + ".ghidrafacts";
		File file = new TextFile(fileName);
		
		var factFactory = new FactFactory();
		var facts = new ArrayList<Fact>() 
		{{
			add(factFactory.createReturnsSelf(decompService, dataFlowGraphService));
			add(factFactory.createNoCallsBefore(decompService));
		}};
		
		for(Fact fact : facts) {
			fact.createFacts(file);
		}
	}

}

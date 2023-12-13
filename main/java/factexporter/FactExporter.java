package factexporter;

import java.util.regex.Pattern;

import export.TextFile;

import ghidra.util.Msg;

import noCallsBefore.NoCallsBefore;
import returnsSelf.ReturnsSelf;

public class FactExporter {
	
	private DecompilationService decompService;
	private DataFlowGraphService dataFlowGraphService;
	
	public FactExporter(DecompilationService decompServ, DataFlowGraphService dataFlowGraphServ) 
	{
		decompService = decompServ;
		dataFlowGraphService = dataFlowGraphServ;
	}
	
	public void CreateFacts() 
	{
		var fileName = "C:/Users/jeroe/Downloads/Facts/Ghidra/" + decompService.decompiledFileName().split(Pattern.quote("."))[0] + ".ghidrafacts";
		var file = new TextFile(fileName);
		new ReturnsSelf(decompService, dataFlowGraphService).CreateFacts(file);
		Msg.out(file.read());
		new NoCallsBefore(decompService).CreateFacts(file);
	}

}

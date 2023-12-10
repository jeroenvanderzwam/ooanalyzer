package factexporter;

import java.util.regex.Pattern;

import dataflow.DataFlowGraphService;
import export.TextFile;

import ghidra.util.Msg;

import noCallsBefore.NoCallsBefore;
import returnsSelf.ReturnsSelf;

public class FactExporter {
	
	private DecompilationService _decompService;
	private DataFlowGraphService _dataFlowGraphService;
	
	public FactExporter(DecompilationService decompService, DataFlowGraphService dataFlowGraphService) 
	{
		_decompService = decompService;
		_dataFlowGraphService = dataFlowGraphService;
	}
	
	public void CreateFacts() 
	{
		var fileName = "C:/Users/jeroe/Downloads/Facts/Ghidra/" + _decompService.decompiledFileName().split(Pattern.quote("."))[0] + ".ghidrafacts";
		var file = new TextFile(fileName);
		new ReturnsSelf(_decompService, _dataFlowGraphService).CreateFacts(file);
		Msg.out(file.read());
		new NoCallsBefore().CreateFacts(_decompService);
	}

}

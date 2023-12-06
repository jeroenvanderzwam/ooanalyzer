package factexporter;


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
		new ReturnsSelf().CreateFacts(_decompService, _dataFlowGraphService);
		new NoCallsBefore();

	}

}

package factexporter;

import java.util.ArrayList;

import noCallsBefore.NoCallsBefore;
import returnsSelf.ReturnsSelf;

public class FactExporter {
	
	private DecompilationService _decompService;
	
	public FactExporter(DecompilationService decompService) 
	{
		_decompService = decompService;
	}
	
	public void CreateFacts() 
	{
		ArrayList<Fact> facts = new ArrayList<Fact>()
		{{
			add(new ReturnsSelf());
			add(new NoCallsBefore());
		}};
		
		for(var fact : facts) 
		{
			fact.CreateFacts(_decompService);
		}
	}

}

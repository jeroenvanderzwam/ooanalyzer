package factexporter;

import java.util.ArrayList;

import facts.Fact;
import facts.NoCallsBefore;
import facts.ReturnsSelf;
import ghidra.app.decompiler.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.*;
import ghidra.util.task.TaskMonitor;

public class FactExporter {
	
	private Program _program;
	
	public FactExporter(Program program) 
	{
		_program = program;
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
			fact.CreateFacts(_program);
		}
	}

}

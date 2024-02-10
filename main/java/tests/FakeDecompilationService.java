package tests;

import java.util.ArrayList;
import java.util.List;

import factexporter.DecompilationService;
import factexporter.datastructures.*;

public class FakeDecompilationService implements DecompilationService
{
	private List<Function> functions;
	
	@Override
	public void initialize() 
	{
		functions = new ArrayList<Function>();
	}
	
	@Override
	public List<Function> functions() 
	{
		return functions;
	}

	@Override
	public CompilerSpecification compilerSpec() 
	{
		var compSpec = new CompilerSpecification("32", "windows");
		return compSpec;
	}

	@Override
	public String decompiledFileName() {
		return "";
	}

	@Override
	public void addFunction(Function func) {
		functions.add(func);
	}

}

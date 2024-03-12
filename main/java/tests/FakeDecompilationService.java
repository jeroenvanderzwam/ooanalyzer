package tests;

import java.util.ArrayList;
import java.util.List;

import factexporter.DecompilationService;
import factexporter.datastructures.*;
import factexporter.facts.Memory;

public class FakeDecompilationService implements DecompilationService
{
	private List<Function> functions;
	private List<Memory> memory;
	
	@Override
	public void initialize() 
	{
		functions = new ArrayList<Function>();
		memory = new ArrayList<Memory>();
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

	@Override
	public void addInitialMemory(String address, String value) {
		memory.add(new Memory(address, value));
	}

	@Override
	public List<Memory> memory() {
		return memory;
	}
}

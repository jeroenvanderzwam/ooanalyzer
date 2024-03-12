package factexporter;

import java.util.List;

import factexporter.datastructures.CompilerSpecification;
import factexporter.datastructures.Function;
import factexporter.facts.Memory;

public interface DecompilationService 
{
	void initialize();
	List<Function> functions();
	List<Memory> memory();
	void addFunction(Function func);
	CompilerSpecification compilerSpec();
	String decompiledFileName();
	void addInitialMemory(String address, String value);
}
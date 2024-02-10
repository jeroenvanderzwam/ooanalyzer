package factexporter;

import java.util.List;

import factexporter.datastructures.CompilerSpecification;
import factexporter.datastructures.Function;

public interface DecompilationService 
{
	void initialize();
	List<Function> functions();
	void addFunction(Function func);
	CompilerSpecification compilerSpec();
	String decompiledFileName();
}
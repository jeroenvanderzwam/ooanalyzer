package factexporter;

import java.util.List;

import factexporter.datastructures.CompilerSpecification;
import factexporter.datastructures.Func;

public interface DecompilationService 
{
	void initialize();
	List<Func> functions();
	CompilerSpecification compilerSpec();
	String decompiledFileName();
}
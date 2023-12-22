package factexporter;

import java.util.List;

import sourcecode.Func;

public interface DecompilationService 
{
	void initialize();
	List<Func> functions();
	CompilerSpecification compilerSpec();
	String decompiledFileName();
}
package factexporter;

import java.util.List;

import sourcecode.Function;

public interface DecompilationService 
{
	List<Function> functions();
	CompilerSpecification compilerSpec();
	String decompiledFileName();
}
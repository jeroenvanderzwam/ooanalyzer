package factexporter;

import java.util.List;

public interface DecompilationService 
{
	List<Function> functions();
	CompilerSpecification compilerSpec();
	String decompiledFileName();
	
	void buildGraph(Function functionName);
	boolean pathFromParamToReturn(Parameter param);
}
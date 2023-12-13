package factexporter;

import ghidra.program.model.lang.CompilerSpec;

public class CompilerSpecificationBuilder 
{
	public CompilerSpecificationBuilder() 
	{
	}
	
	public CompilerSpecification build(CompilerSpec compilerSpec) 
	{
		var id = compilerSpec.getLanguage().getLanguageID().toString();
		var architecture = id.split(":")[2];
		var compilerId = compilerSpec.getCompilerSpecID();
		return new CompilerSpecification(architecture, compilerId.toString());
	}
}

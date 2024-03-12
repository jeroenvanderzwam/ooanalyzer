package factexporter.datastructures;

public class CompilerSpecification 
{
	private String architecture;
	private String compiler;
	
	public CompilerSpecification(String arch, String comp) 
	{
		architecture = arch;
		compiler = comp;
	}
	
	public String getArchitecture() 
	{
		return architecture;
	}
	
	public String getCompiler() 
	{
		return compiler;
	}
}

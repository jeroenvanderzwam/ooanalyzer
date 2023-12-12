package factexporter;

public class CompilerSpecification 
{
	private String architecture;
	private String compiler;
	
	public CompilerSpecification(String arch, String comp) 
	{
		architecture = arch;
		compiler = comp;
	}
	
	public String architecture() 
	{
		return architecture;
	}
	
	public String compiler() 
	{
		return compiler;
	}
}

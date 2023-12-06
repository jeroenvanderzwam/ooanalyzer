package factexporter;

public class CompilerSpecification 
{
	private String _architecture;
	private String _compiler;
	
	public CompilerSpecification(String architecture, String compiler) 
	{
		_architecture = architecture;
		_compiler = compiler;
	}
	
	public String architecture() 
	{
		return _architecture;
	}
	
	public String compiler() 
	{
		return _compiler;
	}
}

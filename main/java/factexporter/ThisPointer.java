package factexporter;

import factexporter.datastructures.CompilerSpecification;

public class ThisPointer
{
	public ThisPointerRegister build(CompilerSpecification compSpecs ) 
	{
		if (compSpecs.architecture().equals("64")) 
		{
			return new VisualStudiox64();
		}
		else if(compSpecs.architecture().equals("32")) 
		{
			return new VisualStudiox32();
		}
		return null;
	}
	
	public interface ThisPointerRegister 
	{
		public String name();
	}
	
	public class VisualStudiox32 implements ThisPointerRegister
	{

		@Override
		public String name() 
		{
			return "ECX";
		}
	}
	
	public class VisualStudiox64 implements ThisPointerRegister
	{

		@Override
		public String name() 
		{
			return "RCX";
		}
		
	}
	
	public class Linuxx64 implements ThisPointerRegister
	{

		@Override
		public String name() 
		{
			return "RDI";
		}
		
	}
}

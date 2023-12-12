package tests;

import java.util.ArrayList;
import java.util.List;

import factexporter.CallingConvention;
import factexporter.CompilerSpecification;
import factexporter.DecompilationService;
import sourcecode.Function;
import sourcecode.Parameter;
import sourcecode.Register;
import sourcecode.Stack;

public class FakeDecompilationService implements DecompilationService
{

	@Override
	public List<Function> functions() 
	{
		var functions = new ArrayList<Function>() 
		{{
			// Parameter is passed in ECX and should therefor be a returnsSelf
			add(new Function("00000001", "FUN_00000001", false, 
					new ArrayList<Parameter>(){{ add(new Parameter("param_1", 4, 0, new Register("ECX"))); }}, 
					new CallingConvention("__thiscall__")));
			
			// Parameter is passed on the stack and should therefor not be a returnsSelf 
			add(new Function("00000002", "FUN_00000002", false, 
					new ArrayList<Parameter>(){{ add(new Parameter("param_1", 4, 0, new Stack())); }}, 
					new CallingConvention("__fastcall__")));
			
			// Function is a thunk, and should therefore not be considered for returnsSelf
			add(new Function("00000003", "FUN_00000003", true, 
					new ArrayList<Parameter>(){{ add(new Parameter("param_1", 4, 0, new Register("ECX"))); }}, 
					new CallingConvention("__fastcall__")));
			
			// No parameters so cannot be returnsSelf
			add(new Function("00000004", "FUN_00000004", false, 
					new ArrayList<Parameter>(), 
					new CallingConvention("__fastcall__")));
			
		}};
		return functions;
	}

	@Override
	public CompilerSpecification compilerSpec() 
	{
		var compSpec = new CompilerSpecification("32", "windows");
		return compSpec;
	}

	@Override
	public String decompiledFileName() {
		return "";
	}

}

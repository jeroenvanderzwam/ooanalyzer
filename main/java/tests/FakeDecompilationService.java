package tests;

import java.util.ArrayList;
import java.util.List;

import factexporter.DecompilationService;
import factexporter.datastructures.CallingConvention;
import factexporter.datastructures.CompilerSpecification;
import factexporter.datastructures.Func;
import factexporter.datastructures.Function;
import factexporter.datastructures.Parameter;
import factexporter.datastructures.Register;
import factexporter.datastructures.Stack;
import factexporter.datastructures.ThunkFunction;

public class FakeDecompilationService implements DecompilationService
{
	private List<Func> functions;
	@Override
	public void initialize() 
	{
		functions = new ArrayList<Func>() 
		{{
			// Parameter is passed in ECX and should therefore be a returnsSelf
			add(new Function("00000001", "FUN_00000001", 
					new ArrayList<Parameter>(){{ add(new Parameter("param_1", 4, 0, new Register("ECX"))); }}, 
					new CallingConvention("__thiscall__")));
			
			// Parameter is passed on the stack and should therefore not be a returnsSelf 
			add(new Function("00000002", "FUN_00000002", 
					new ArrayList<Parameter>(){{ add(new Parameter("param_1", 4, 0, new Stack())); }}, 
					new CallingConvention("__fastcall__")));
			
			// Function is a thunk, and should therefore not be considered for returnsSelf
			add(new ThunkFunction("00000003", "FUN_00000003", 
					new ArrayList<Parameter>(){{ add(new Parameter("param_1", 4, 0, new Register("ECX"))); }}, 
					new CallingConvention("__fastcall__")));
			
			// No parameters so cannot be returnsSelf
			add(new Function("00000004", "FUN_00000004", new ArrayList<Parameter>(), new CallingConvention("__fastcall__")));
			
		}};
	}
	
	@Override
	public List<Func> functions() 
	{
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

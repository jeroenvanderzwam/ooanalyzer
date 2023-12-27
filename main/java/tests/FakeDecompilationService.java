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

class FakeDecompilationService implements DecompilationService
{
	private List<Func> functions;
	
	@Override
	public void initialize() 
	{
		functions = new ArrayList<Func>() 
		{{
			add(validReturnsSelfFunction());
			add(invalidReturnsSelfBecauseOnStack());
			add(invalidBecauseThunk());
			add(invalidBecauseNoParameters());
			add(invalidBecauseNotECXRegister());
		}};
	}
		
	private Func validReturnsSelfFunction() {
		return new Function("00000001", "FUN_00000001", 
				new ArrayList<Parameter>(){{ add(new Parameter("param_1", 4, 0, new Register("ECX"))); }}, 
				new CallingConvention("__thiscall__"));
	}
	
	private Func invalidReturnsSelfBecauseOnStack() {
		return new Function("00000002", "FUN_00000002", 
				new ArrayList<Parameter>(){{ add(new Parameter("param_1", 4, 0, new Stack())); }}, 
				new CallingConvention("__fastcall__"));
	}
	
	private Func invalidBecauseThunk() {
		return new ThunkFunction("00000003", "FUN_00000003", 
				new ArrayList<Parameter>(){{ add(new Parameter("param_1", 4, 0, new Register("ECX"))); }}, 
				new CallingConvention("__fastcall__"));
	}
	
	private Func invalidBecauseNoParameters() {
		return new Function("00000004", "FUN_00000004", new ArrayList<Parameter>(), new CallingConvention("__fastcall__"));
	}
	
	private Func invalidBecauseNotECXRegister() {
		return new Function("00000005", "FUN_00000005", 
				new ArrayList<Parameter>(){{ add(new Parameter("param_1", 4, 0, new Register("EAX"))); }}, 
				new CallingConvention("__thiscall__"));
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

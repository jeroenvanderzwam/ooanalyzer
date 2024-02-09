package tests;

import java.util.ArrayList;
import java.util.List;

import factexporter.DecompilationService;
import factexporter.datastructures.CallingConvention;
import factexporter.datastructures.CompilerSpecification;
import factexporter.datastructures.*;

class FakeDecompilationService implements DecompilationService
{
	private List<Function> functions;
	
	@Override
	public void initialize() 
	{
		functions = new ArrayList<Function>() 
		{{
			add(validReturnsSelfFunction());
			add(invalidReturnsSelfBecauseOnStack());
			add(invalidBecauseThunk());
			add(invalidBecauseNoParameters());
			add(invalidBecauseNotECXRegister());
		}};
	}
		
	private Function validReturnsSelfFunction() {

		return Function.createFunction("00000001", "FUN_00000001", 
				new ArrayList<Value>(){{ add(Value.createParameter("param_1", 4, 0, Storage.createRegister("ECX"))); }}, 
				new CallingConvention("__thiscall__"), new ArrayList<FunctionCallInstruction>());
	}
	
	private Function invalidReturnsSelfBecauseOnStack() {
		return Function.createFunction("00000002", "FUN_00000002", 
				new ArrayList<Value>(){{ add(Value.createParameter("param_1", 4, 0, Storage.createStack(0))); }}, 
				new CallingConvention("__fastcall__"), new ArrayList<FunctionCallInstruction>());
	}
	
	private Function invalidBecauseThunk() {
		return Function.createThunkFunction("00000003", "FUN_00000003", 
				new ArrayList<Value>(){{ add(Value.createParameter("param_1", 4, 0, Storage.createRegister("ECX"))); }}, 
				new CallingConvention("__fastcall__"), new ArrayList<FunctionCallInstruction>());
	}
	
	private Function invalidBecauseNoParameters() {
		return Function.createFunction("00000004", "FUN_00000004", new ArrayList<Value>(), 
				new CallingConvention("__fastcall__"), new ArrayList<FunctionCallInstruction>());
	}
	
	private Function invalidBecauseNotECXRegister() {
		return Function.createFunction("00000005", "FUN_00000005", 
				new ArrayList<Value>(){{ add(Value.createParameter("param_1", 4, 0, Storage.createRegister("EAX"))); }}, 
				new CallingConvention("__thiscall__"), new ArrayList<FunctionCallInstruction>());
	}
	
	@Override
	public List<Function> functions() 
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

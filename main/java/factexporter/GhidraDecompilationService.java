package factexporter;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.FunctionPrototype;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.VarnodeAST;
import ghidra.util.Msg;

public class GhidraDecompilationService implements DecompilationService
{
	private Program _program;
	private HashMap<String, HighFunction> _decompiledFunctions = new HashMap<String, HighFunction>();
	private ArrayList<Function> _functions = new ArrayList<Function>();
	
	GhidraDecompilationService(Program program) 
	{
		_program = program;
	}
	
	public HashMap<String, HighFunction> decompiledFunctions() 
	{
		if (_decompiledFunctions.isEmpty()) 
		{
			var decompInterface = new DecompInterface();
			decompInterface.openProgram(_program);
			var funcIter = _program.getListing().getFunctions(true);
			while (funcIter.hasNext()) 
			{	
				var function = funcIter.next();
				var res = decompInterface.decompileFunction(function, 30, null);
				var highFunction = res.getHighFunction();
				_decompiledFunctions.put(function.getName(), highFunction);
			}
		}
		return _decompiledFunctions;
	}
	
	private ArrayList<String> preferredParameterLocations(ghidra.program.model.listing.Function function, PrototypeModel callingConv) 
	{
		var preferredParameterLocation = new ArrayList<String>();
		for (int i = 0; i < function.getParameterCount(); i++) {
			var paramDatatype = function.getParameter(i).getDataType();
			var firstArgLocation = callingConv.getArgLocation(i, function.getParameters(), paramDatatype, _program);
			if (firstArgLocation.isRegisterStorage()) {
				var register = firstArgLocation.getRegister();
				preferredParameterLocation.add(register.getName());
			} else if (firstArgLocation.isStackStorage()) {
				preferredParameterLocation.add("Stack");
			}
		}
		return preferredParameterLocation;
	}
	
	private ArrayList<Parameter> parameters(FunctionPrototype funcPrototype) {
		var parameters = new ArrayList<Parameter>();
		for (int i = 0; i < funcPrototype.getNumParams(); i++) {
			var firstParamaterSymbol = funcPrototype.getParam(i);
			var register = firstParamaterSymbol.getStorage().getRegister();
			
			var parameter = new Parameter(firstParamaterSymbol.getName(), 
							i, 
							register != null ? new Register( register.getName()) : null);
			parameters.add(parameter);
		}
		return parameters;
	}

	@Override
	public List<Function> functions() {
		if (_functions.isEmpty()) {
			for (var highFunction : decompiledFunctions().values()) 
			{		
				var function = highFunction.getFunction();
				var ghidraCallingConv = function.getCallingConvention();
				CallingConvention callingConvention = null;
				if (ghidraCallingConv != null) {
					callingConvention = new CallingConvention(ghidraCallingConv.getName());
				}
				
				var funcPrototype = highFunction.getFunctionPrototype();
				var parameters = parameters(funcPrototype);
		
				var func = new Function(function.getEntryPoint().toString(), 
										function.getName(), 
										function.isThunk(), 
										parameters, 
										callingConvention != null ? callingConvention : null);
				_functions.add(func);
			}
		}
		return _functions;
	}

	@Override
	public CompilerSpecification compilerSpec() {
		var compilerSpec = _program.getCompilerSpec();
		var id = compilerSpec.getLanguage().getLanguageID().toString();
		var architecture = id.split(":")[2];
		var compilerId = compilerSpec.getCompilerSpecID();
		return new CompilerSpecification(architecture, compilerId.toString());
	}

	@Override
	public String decompiledFileName() {
		return _program.getDomainFile().getName();
	}
}

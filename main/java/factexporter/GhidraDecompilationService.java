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
import returnsSelf.GhidraDataflowGraph;

public class GhidraDecompilationService implements DecompilationService
{
	private Program _program;
	private HashMap<String, HighFunction> _decompiledFunctions = new HashMap<String, HighFunction>();
	private GhidraDataflowGraph _graph;
	private String _graphFunction;
	
	GhidraDecompilationService(Program program) 
	{
		_program = program;
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
		var functions = new ArrayList<Function>();
		var decompInterface = new DecompInterface();
		decompInterface.openProgram(_program);
		var funcIter = _program.getListing().getFunctions(true);
		while (funcIter.hasNext()) 
		{	
			var function = funcIter.next();
			var ghidraCallingConv = function.getCallingConvention();
			CallingConvention callingConvention = null;
			if (ghidraCallingConv != null) {
				callingConvention = new CallingConvention(ghidraCallingConv.getName(),preferredParameterLocations(function, ghidraCallingConv));
			}
			
			var res = decompInterface.decompileFunction(function, 30, null);
			var highFunction = res.getHighFunction();
			_decompiledFunctions.put(function.getName(), highFunction);
			
			var funcPrototype = highFunction.getFunctionPrototype();
			var parameters = parameters(funcPrototype);

			var func = new Function(function.getEntryPoint().toString(), 
									function.getName(), 
									function.isThunk(), 
									parameters, 
									callingConvention != null ? callingConvention : null);
			functions.add(func);
		}
		
		return functions;
	}

	@Override
	public CompilerSpecification compilerSpec() {
		var compilerSpec = _program.getCompilerSpec();
		var callingConventions = compilerSpec.getCallingConventions();
		var default_ = compilerSpec.getDefaultCallingConvention();
		var language = compilerSpec.getLanguage();
		var stackPointer = compilerSpec.getStackPointer();
		var properties = compilerSpec.getPropertyKeys();
		return null;
	}

	@Override
	public String decompiledFileName() {
		return _program.getDomainFile().getName();
	}

	@Override
	public void buildGraph(Function function) {
		_graphFunction = function.name();
		_graph = new GhidraDataflowGraph(_decompiledFunctions.get(function.name()));
		_graph.buildGraph();
	}

	@Override
	public boolean pathFromParamToReturn(Parameter param) {
		var function = _decompiledFunctions.get(_graphFunction);
		var prototype = function.getFunctionPrototype();
		var symbol = prototype.getParam(param.index());
		var variable = symbol.getHighVariable();
		var registerLocation = (VarnodeAST)variable.getRepresentative();
		return _graph.pathFromParamToReturn(registerLocation);
	}
}

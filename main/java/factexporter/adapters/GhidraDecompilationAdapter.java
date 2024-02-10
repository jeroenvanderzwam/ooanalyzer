package factexporter.adapters;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import factexporter.DecompilationService;
import factexporter.datastructures.CompilerSpecification;
import factexporter.datastructures.Function;
import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;

public class GhidraDecompilationAdapter implements DecompilationService
{
	private Program program;
	private HashMap<String, HighFunction> _decompiledFunctions = new HashMap<String, HighFunction>();
	private ArrayList<Function> functions = new ArrayList<Function>();
	
	public GhidraDecompilationAdapter(Program prog) 
	{
		program = prog;
	}
	
	public void initialize() 
	{
		decompiledFunctions();
	}
	
	@Override
	public List<Function> functions() {
		if (functions.isEmpty()) {
			for (var highFunction : decompiledFunctions().values()) 
			{		
				var func = new FunctionBuilder().build(highFunction);
				addFunction(func);
			}
		}
		return functions;
	}

	@Override
	public CompilerSpecification compilerSpec() 
	{
		var compilerSpec = program.getCompilerSpec();
		return new CompilerSpecificationBuilder().build(compilerSpec);
	}

	@Override
	public String decompiledFileName() {
		return program.getDomainFile().getName();
	}
	
	public HashMap<String, HighFunction> decompiledFunctions() 
	{
		if (_decompiledFunctions.isEmpty()) 
		{
			var decompInterface = new DecompInterface();
			decompInterface.openProgram(program);
			var funcIter = program.getListing().getFunctions(true);
			while (funcIter.hasNext()) 
			{	
				var function = funcIter.next();
				var res = decompInterface.decompileFunction(function, 30, null);
				var highFunction = res.getHighFunction();
				_decompiledFunctions.put(function.getEntryPoint().toString(), highFunction);
			}
		}
		return _decompiledFunctions;
	}

	@Override
	public void addFunction(Function func) {
		functions.add(func);
	}
}
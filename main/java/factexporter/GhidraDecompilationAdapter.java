package factexporter;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;

import sourcecode.Func;

public class GhidraDecompilationAdapter implements DecompilationService
{
	private Program program;
	private HashMap<String, HighFunction> _decompiledFunctions = new HashMap<String, HighFunction>();
	private ArrayList<Func> functions = new ArrayList<Func>();
	
	GhidraDecompilationAdapter(Program prog) 
	{
		program = prog;
	}
	
	@Override
	public List<Func> functions() {
		if (functions.isEmpty()) {
			for (var highFunction : decompiledFunctions().values()) 
			{		
				var func = new FunctionBuilder().build(highFunction);
				functions.add(func);
			}
		}
		return functions;
	}

	@Override
	public CompilerSpecification compilerSpec() {
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
				_decompiledFunctions.put(function.getName(), highFunction);
			}
		}
		return _decompiledFunctions;
	}
}

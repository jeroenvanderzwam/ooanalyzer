package factexporter;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighConstant;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighGlobal;
import ghidra.program.model.pcode.HighLocal;
import ghidra.program.model.pcode.HighOther;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import sourcecode.Constant;
import sourcecode.Function;
import sourcecode.FunctionCall;
import sourcecode.Instruction;
import sourcecode.OtherInstruction;
import sourcecode.OtherValue;
import sourcecode.Parameter;
import sourcecode.Register;
import sourcecode.Value;
import sourcecode.Variable;

public class GhidraDecompilationAdapter implements DecompilationService
{
	private Program program;
	private HashMap<String, HighFunction> _decompiledFunctions = new HashMap<String, HighFunction>();
	private ArrayList<Function> functions = new ArrayList<Function>();
	
	GhidraDecompilationAdapter(Program prog) 
	{
		program = prog;
	}
	
	@Override
	public List<Function> functions() {
		if (functions.isEmpty()) {
			for (var highFunction : decompiledFunctions().values()) 
			{		
				var func = new FunctionConverter().convert(highFunction);
				functions.add(func);
			}
		}
		return functions;
	}

	@Override
	public CompilerSpecification compilerSpec() {
		var compilerSpec = program.getCompilerSpec();
		var id = compilerSpec.getLanguage().getLanguageID().toString();
		var architecture = id.split(":")[2];
		var compilerId = compilerSpec.getCompilerSpecID();
		return new CompilerSpecification(architecture, compilerId.toString());
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

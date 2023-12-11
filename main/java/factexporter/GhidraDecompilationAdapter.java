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
	private Program _program;
	private HashMap<String, HighFunction> _decompiledFunctions = new HashMap<String, HighFunction>();
	private ArrayList<Function> _functions = new ArrayList<Function>();
	
	GhidraDecompilationAdapter(Program program) 
	{
		_program = program;
	}
	
	@Override
	public List<Function> functions() {
		if (_functions.isEmpty()) {
			for (var highFunction : decompiledFunctions().values()) 
			{		
				var func = new ConvertFunction().convert(highFunction);
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
}

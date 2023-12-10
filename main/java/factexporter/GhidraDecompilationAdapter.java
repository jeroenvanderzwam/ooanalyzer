package factexporter;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.FunctionPrototype;
import ghidra.program.model.pcode.HighConstant;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighGlobal;
import ghidra.program.model.pcode.HighLocal;
import ghidra.program.model.pcode.HighOther;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeOp;
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
	
	private ArrayList<Parameter> parameters(FunctionPrototype funcPrototype) {
		var parameters = new ArrayList<Parameter>();
		for (int i = 0; i < funcPrototype.getNumParams(); i++) {
			var firstParamaterSymbol = funcPrototype.getParam(i);
			var register = firstParamaterSymbol.getStorage().getRegister();
			
			var parameter = new Parameter(firstParamaterSymbol.getName(), 
							firstParamaterSymbol.getSize(),
							i, 
							register != null ? new Register( register.getName()) : null);
			parameters.add(parameter);
		}
		return parameters;
	}
	
	private Value toValue(HighVariable variable) 
	{
		if (variable instanceof HighConstant) {
			var constant = (HighConstant)variable;
			return new Constant(constant.getScalar().toString(), constant.getSize());
		} else if(variable instanceof HighOther) {
			var highOther = (HighOther)variable;
			return new Variable(highOther.getName(), highOther.getSize());
		} else if (variable instanceof HighLocal) {
			var highLocal = (HighLocal)variable;
			return new Variable(highLocal.getSymbol().getName(), highLocal.getSize());
		} else if (variable instanceof HighGlobal){
			var highGlobal = (HighGlobal)variable;
			return new Variable(highGlobal.getName(), highGlobal.getSize());
		} else {
			return new OtherValue(0);
		}
	}

	@Override
	public List<Function> functions() {
		if (_functions.isEmpty()) {
			for (var highFunction : decompiledFunctions().values()) 
			{		
				var pCodeOps = highFunction.getPcodeOps();
				var instructions = new ArrayList<Instruction>();
				while (pCodeOps.hasNext())
				{
					var op = pCodeOps.next();
					var mnemonic = op.getMnemonic();
					var output = op.getOutput();
					var inputs = op.getInputs();
					if (op.getOpcode() == PcodeOp.CALL) {
						var values = new ArrayList<Value>();
						for(int i = 1; i < inputs.length; i++)
						{
							var variable = inputs[0].getHigh();
							values.add(toValue(variable));
						}
						instructions.add(new FunctionCall(inputs[0].getAddress().toString(), values, output != null ? toValue(output.getHigh()) : null));

					} else {
						var values = new ArrayList<Value>();
						for(var input : inputs)
						{
							var variable = input.getHigh();
							values.add(toValue(variable));
						}
						instructions.add(new OtherInstruction(mnemonic, values, output != null ? toValue(output.getHigh()) : null));
					}

				}
				
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
										callingConvention != null ? callingConvention : null,
										instructions);
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

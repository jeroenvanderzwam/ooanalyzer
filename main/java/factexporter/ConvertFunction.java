package factexporter;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import ghidra.program.model.pcode.HighConstant;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighGlobal;
import ghidra.program.model.pcode.HighLocal;
import ghidra.program.model.pcode.HighOther;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
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

public class ConvertFunction 
{
	
	ConvertFunction() 
	{
	}
	
	public Function convert(HighFunction highFunction) 
	{
		var function = highFunction.getFunction();
		
		var instructions = convertInstructions(highFunction.getPcodeOps());
		var callingConvention = convertCallingConvention(highFunction);
		var parameters = convertParameters(highFunction);
		var func = new Function(function.getEntryPoint().toString(), 
								function.getName(), 
								function.isThunk(), 
								parameters, 
								callingConvention != null ? callingConvention : null,
								instructions);
		return func;
	}
	
	private List<Instruction> convertInstructions(Iterator<PcodeOpAST> pCodeOps) 
	{
		var instructions = new ArrayList<Instruction>();
		while (pCodeOps.hasNext())
		{
			instructions.add(convertInstruction(pCodeOps.next()));
		}
		return instructions;
	}
	
	private CallingConvention convertCallingConvention(HighFunction highFunction) 
	{
		var ghidraCallingConv = highFunction.getFunction().getCallingConvention();
		if (ghidraCallingConv != null) {
			return new CallingConvention(ghidraCallingConv.getName());
		}
		return null;
	}
	
	private ArrayList<Parameter> convertParameters(HighFunction highFunction) {
		var funcPrototype = highFunction.getFunctionPrototype();
		var parameters = new ArrayList<Parameter>();
		for (int i = 0; i < funcPrototype.getNumParams(); i++) {
			var param = funcPrototype.getParam(i);
			parameters.add(convertParameter(i,param));
		}
		return parameters;
	}

	private Instruction convertInstruction(PcodeOpAST op) 
	{
		var mnemonic = op.getMnemonic();
		var output = op.getOutput();
		var inputs = op.getInputs();
		if (op.getOpcode() == PcodeOp.CALL) {
			return new FunctionCall(inputs[0].getAddress().toString(), convertVariables(inputs), 
					output != null ? convertVariable(output) : null);
		}
		return new OtherInstruction(mnemonic, convertVariables(inputs), 
				output != null ? convertVariable(output) : null);
	}
	
	private Parameter convertParameter(int index, HighSymbol param) 
	{
		var register = param.getStorage().getRegister();
		return new Parameter(param.getName(), param.getSize(), index, 
						register != null ? new Register( register.getName()) : null);
	}
	
	private List<Value> convertVariables(Varnode[] inputs) 
	{
		var values = new ArrayList<Value>();
		for(var input : inputs)
		{
			values.add(convertVariable(input));
		}
		return values;
	}
	
	private Value convertVariable(Varnode output) 
	{
		var variable = output.getHigh();
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
}

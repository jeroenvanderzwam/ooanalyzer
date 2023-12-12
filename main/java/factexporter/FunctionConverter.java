package factexporter;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import sourcecode.Function;
import sourcecode.FunctionCall;
import sourcecode.Instruction;
import sourcecode.OtherInstruction;
import sourcecode.Parameter;
import sourcecode.Register;
import sourcecode.Stack;
import sourcecode.Storage;
import sourcecode.Value;

public class FunctionConverter 
{
	
	FunctionConverter() 
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
		var outputVar = output != null ? convertVariable(output) : null;
		if (op.getOpcode() == PcodeOp.CALL) {
			return new FunctionCall(inputs[0].getAddress().toString(), convertVariables(inputs), outputVar);
		}
		return new OtherInstruction(mnemonic, convertVariables(inputs), outputVar);
	}
	
	private Parameter convertParameter(int index, HighSymbol param) 
	{
		Storage storage = null;
		var register = param.getStorage().getRegister();
		if (register != null) {
			storage = new Register(register.getName());
		}
		else if (param.getStorage().isStackStorage()) {
			storage = new Stack();
		}
		return new Parameter(param.getName(), param.getSize(), index, storage);
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
		return new ValueBuilder().build(output);
	}
}

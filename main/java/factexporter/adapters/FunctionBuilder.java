package factexporter.adapters;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import factexporter.datastructures.CallingConvention;
import factexporter.datastructures.Func;
import factexporter.datastructures.Function;
import factexporter.datastructures.FunctionCall;
import factexporter.datastructures.Instruction;
import factexporter.datastructures.OtherInstruction;
import factexporter.datastructures.Parameter;
import factexporter.datastructures.Register;
import factexporter.datastructures.Stack;
import factexporter.datastructures.Storage;
import factexporter.datastructures.ThunkFunction;
import factexporter.datastructures.Value;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;

public class FunctionBuilder 
{
	
	FunctionBuilder() 
	{
	}
	
	public Func build(HighFunction highFunction) 
	{
		var function = highFunction.getFunction();
		
		var instructions = buildInstructions(highFunction.getPcodeOps());
		var callingConvention = buildCallingConvention(highFunction);
		var parameters = buildParameters(highFunction);
		Func func;
		if (!function.isThunk()) {
			func = new Function(function.getEntryPoint().toString(), function.getName(), parameters, callingConvention, instructions);
		} else {
			func = new ThunkFunction(function.getEntryPoint().toString(), function.getName(), parameters, callingConvention , instructions);
		}
		return func;
	}
	
	private List<Instruction> buildInstructions(Iterator<PcodeOpAST> pCodeOps) 
	{
		var instructions = new ArrayList<Instruction>();
		while (pCodeOps.hasNext())
		{
			instructions.add(buildInstruction(pCodeOps.next()));
		}
		return instructions;
	}
	
	private CallingConvention buildCallingConvention(HighFunction highFunction) 
	{
		var ghidraCallingConv = highFunction.getFunction().getCallingConvention();
		if (ghidraCallingConv != null) {
			return new CallingConvention(ghidraCallingConv.getName());
		}
		return new CallingConvention("No calling convention available");
	}
	
	private ArrayList<Parameter> buildParameters(HighFunction highFunction) {
		var funcPrototype = highFunction.getFunctionPrototype();
		var parameters = new ArrayList<Parameter>();
		for (int i = 0; i < funcPrototype.getNumParams(); i++) {
			var param = funcPrototype.getParam(i);
			parameters.add(buildParameter(i,param));
		}
		return parameters;
	}

	private Instruction buildInstruction(PcodeOpAST op) 
	{
		var mnemonic = op.getMnemonic();
		var output = op.getOutput();
		var inputs = op.getInputs();
		var outputVar = output != null ? buildVariable(output) : null;
		if (op.getOpcode() == PcodeOp.CALL) {
			return new FunctionCall(inputs[0].getAddress().toString(), buildVariables(inputs), outputVar);
		}
		return new OtherInstruction(mnemonic, buildVariables(inputs), outputVar);
	}
	
	private Parameter buildParameter(int index, HighSymbol param) 
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
	
	private List<Value> buildVariables(Varnode[] inputs) 
	{
		var values = new ArrayList<Value>();
		for(var input : inputs)
		{
			values.add(buildVariable(input));
		}
		return values;
	}
	
	private Value buildVariable(Varnode output) 
	{
		return new ValueBuilder().build(output);
	}
}

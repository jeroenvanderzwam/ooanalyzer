package factexporter.adapters;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

import factexporter.datastructures.CallingConvention;
import factexporter.datastructures.*;
import ghidra.program.model.pcode.*;

class FunctionBuilder {
	
	public Function build(HighFunction highFunction) {
		var function = highFunction.getFunction();
		var instructions = buildFunctionCallInstructions(highFunction.getPcodeOps());
		var callingConvention = buildCallingConvention(highFunction);
		var parameters = buildParameters(highFunction);
		Function func;
		if (!function.isThunk()) {
			func = Function.createFunction(function.getEntryPoint().toString(), function.getName(), parameters, callingConvention,
					instructions);
		} else {
			func = Function.createThunkFunction(function.getEntryPoint().toString(), function.getName(), parameters,
					callingConvention, instructions);
		}
		return func;
	}

	private List<FunctionCallInstruction> buildFunctionCallInstructions(Iterator<PcodeOpAST> pCodeOps) {
		var instructions = new ArrayList<FunctionCallInstruction>();
		while (pCodeOps.hasNext()) {
			var op = pCodeOps.next();
			if (op.getOpcode() == PcodeOp.CALL) {
				instructions.add(buildFunctionCallInstruction(op));
			}
		}
		return instructions;
	}

	private CallingConvention buildCallingConvention(HighFunction highFunction) {
		var ghidraCallingConv = highFunction.getFunction().getCallingConvention();
		if (ghidraCallingConv != null) {
			return new CallingConvention(ghidraCallingConv.getName());
		}
		return CallingConvention.createInvalidCallingConvention();
	}

	private ArrayList<Value> buildParameters(HighFunction highFunction) {
		var funcPrototype = highFunction.getFunctionPrototype();
		var parameters = new ArrayList<Value>();
		for (int i = 0; i < funcPrototype.getNumParams(); i++) {
			var param = funcPrototype.getParam(i);
			parameters.add(buildParameter(i, param));
		}
		return parameters;
	}

	private FunctionCallInstruction buildFunctionCallInstruction(PcodeOpAST op) {
		var output = op.getOutput();
		var inputs = op.getInputs();
		var instructionAddress = op.getSeqnum().getTarget();
		var outputVar = output != null ? buildVariable(output) : null;
		
		var calledFunctionAddress = inputs[0].getAddress().toString();
		var arguments = Arrays.asList(inputs).subList(1, inputs.length);
		return new FunctionCallInstruction(instructionAddress.toString(), calledFunctionAddress, buildVariables(arguments), outputVar);
	}

	private Value buildParameter(int index, HighSymbol param) {
		Storage storage = null;
		var register = param.getStorage().getRegister();
		if (register != null) {
			storage = Storage.createRegister(register.getName());
		} else if (param.getStorage().isStackStorage()) {
			storage = Storage.createStack(param.getStorage().getStackOffset());
		}
		return Value.createParameter(param.getName(), param.getSize(), index, storage);
	}

	private List<Value> buildVariables(List<Varnode> inputs) {
		var values = new ArrayList<Value>();
		for (var input : inputs) {
			values.add(buildVariable(input));
		}
		return values;
	}

	private Value buildVariable(Varnode output) {
		return new ValueBuilder().build(output);
	}
}

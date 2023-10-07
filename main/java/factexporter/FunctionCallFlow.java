package factexporter;

import ghidra.util.Msg;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.address.*;

public class FunctionCallFlow {
	
	public void run(Program program) 
	{
		String depth = "";
		Function startingPoint = program.getListing().getGlobalFunctions("entry").get(0);
		Address addr = startingPoint.getEntryPoint();
		Instruction instruction = program.getListing().getInstructionAt(addr);
		Instruction returnInstruction = null;
        while (true) {
        	
            RefType instructionType = instruction.getFlowType();

            if (instructionType == RefType.UNCONDITIONAL_CALL) 
            {
            	var addresses = instruction.getFlows();
            	assert addresses.length == 1;
            	Function function = program.getListing().getFunctionAt(addresses[0]);

            	returnInstruction = instruction;
            	instruction = program.getListing().getInstructionAt(addresses[0]);
            	Msg.out(depth + function.getName() + (function.isThunk() ? " (thunk)" : ""));
            	depth += "\t";
            }
            else if (instructionType == RefType.CONDITIONAL_CALL) {
            	Msg.out(instruction);
            }
            else if (instructionType == RefType.UNCONDITIONAL_JUMP) 
            {
            	var addresses = instruction.getFlows();
            	assert addresses.length == 1;
            	instruction = program.getListing().getInstructionAt(addresses[0]);
            	
            }
            else if (instructionType == RefType.COMPUTED_CALL)
            {
            	var addresses = instruction.getFlows();
            	assert addresses.length == 1;
            	instruction = instruction.getNext();
            	if (addresses.length > 0) 
            	{
            		Function function = program.getListing().getFunctionAt(addresses[0]);
            		if (function != null ) 
            		{
            			Msg.out(depth + function.getName() + " Computed");
            		}
            	}
            }
            else if (instructionType == RefType.CONDITIONAL_JUMP)
            {
            	var addresses = instruction.getFlows();
            	assert addresses.length == 1;
            	instruction = program.getListing().getInstructionAt(addresses[0]);
            }
            else if (instructionType == RefType.COMPUTED_JUMP)
            {
            	var addresses = instruction.getFlows();
            	assert addresses.length == 1;
            	instruction = instruction.getNext();
            }
            else if (instructionType == RefType.TERMINATOR)
            {
            	depth = depth.replaceFirst("\t", "");
            	instruction = returnInstruction.getNext();
            }
            else 
            {
            	instruction = instruction.getNext();
            }  
        }
	}
	
}
package factexporter;

import ghidra.util.Msg;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.address.*;

public class ControlFlow {
	
	public void run(Program program) 
	{
		Function startingPoint = program.getListing().getGlobalFunctions("entry").get(0);
		Address addr = startingPoint.getEntryPoint();
		Instruction instruction = program.getListing().getInstructionAt(addr);
        while (true) {
        	
            RefType t = instruction.getFlowType();

            if (t == RefType.UNCONDITIONAL_CALL) 
            {
            	var addresses = instruction.getFlows();
            	instruction = program.getListing().getInstructionAt(addresses[0]);
            	Function function = program.getListing().getFunctionAt(addresses[0]);
            	Msg.out("Call to: " + function.getName());
            }
            else if (t == RefType.UNCONDITIONAL_JUMP) 
            {
            	var addresses = instruction.getFlows();
            	instruction = program.getListing().getInstructionAt(addresses[0]);
            	Function function = program.getListing().getFunctionAt(addresses[0]);
            	if (function != null) 
            	{
            		Msg.out("Unconditional jump to: " + function.getName());
            	}
            	
            }
            else 
            {
            	instruction = instruction.getNext();
            	Msg.out(t.toString() + "---"+ instruction);
            }  
        }
	}
	
}
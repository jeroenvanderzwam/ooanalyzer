package facts;

import factexporter.DataflowGraph;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;

public class ReturnsSelf implements Fact{

	@Override
	public void CreateFacts(Program program) {
		DecompInterface decompInterface = new DecompInterface();
		decompInterface.openProgram(program);
		var funcIter = program.getListing().getFunctions(true);
		while (funcIter.hasNext()) 
		{	
			Function function = funcIter.next();
			if (function.isThunk()) { continue; }
			DecompileResults res = decompInterface.decompileFunction(function, 30, null);
			HighFunction highFunction = res.getHighFunction();
	
			FunctionPrototype funcPrototype = highFunction.getFunctionPrototype();
			if (funcPrototype.getNumParams() == 0) { continue ;}
			
			HighSymbol firstParamaterSymbol = funcPrototype.getParam(0);
			HighVariable firstParamaterVariable = firstParamaterSymbol.getHighVariable();
			VarnodeAST firstParameterVarnode = (VarnodeAST)firstParamaterVariable.getRepresentative();
			DataflowGraph graph = new DataflowGraph(highFunction);
			graph.buildGraph();
			graph.checkIfReturnsSelf(firstParameterVarnode);
		}
	}
	
}

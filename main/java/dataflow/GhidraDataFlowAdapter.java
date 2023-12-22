package dataflow;

import factexporter.DataFlowGraphService;
import factexporter.GhidraDecompilationAdapter;
import ghidra.program.model.pcode.VarnodeAST;
import ghidra.util.Msg;
import sourcecode.Func;
import sourcecode.Parameter;

public class GhidraDataFlowAdapter implements DataFlowGraphService 
{
	private GhidraDecompilationAdapter ghidraDecompilationService;
	private GhidraDataflowPathFinder graph;
	private String graphFunction;
	
	public GhidraDataFlowAdapter(GhidraDecompilationAdapter ghidraDecompService) 
	{
		ghidraDecompilationService = ghidraDecompService;
	}
	
	@Override
	public void buildGraph(Func function) {
		graphFunction = function.address();
		graph = new GhidraDataflowPathFinder(ghidraDecompilationService.decompiledFunctions().get(graphFunction));
		graph.buildGraph();
	}

	@Override
	public boolean pathFromParamToReturn(Parameter param) {
		var function = ghidraDecompilationService.decompiledFunctions().get(graphFunction);
		var prototype = function.getFunctionPrototype();
		var symbol = prototype.getParam(param.index());
		var variable = symbol.getHighVariable();
		if (variable != null) {
			var registerLocation = (VarnodeAST)variable.getRepresentative();
			return graph.pathFromParamToReturn(registerLocation);
		}
		return false;
	}

}

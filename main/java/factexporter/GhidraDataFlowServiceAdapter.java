package factexporter;

import java.util.HashMap;

import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.VarnodeAST;

public class GhidraDataFlowServiceAdapter implements DataFlowGraphService 
{
	private GhidraDecompilationService _ghidraDecompilationService;
	private GhidraDataflowGraph _graph;
	private String _graphFunction;
	
	public GhidraDataFlowServiceAdapter(GhidraDecompilationService ghidraDecompilationService) 
	{
		_ghidraDecompilationService = ghidraDecompilationService;
	}
	
	@Override
	public void buildGraph(Function function) {
		_graphFunction = function.name();
		_graph = new GhidraDataflowGraph(_ghidraDecompilationService.decompiledFunctions().get(function.name()));
		_graph.buildGraph();
	}

	@Override
	public boolean pathFromParamToReturn(Parameter param) {
		var function = _ghidraDecompilationService.decompiledFunctions().get(_graphFunction);
		var prototype = function.getFunctionPrototype();
		var symbol = prototype.getParam(param.index());
		var variable = symbol.getHighVariable();
		var registerLocation = (VarnodeAST)variable.getRepresentative();
		return _graph.pathFromParamToReturn(registerLocation);
	}

}

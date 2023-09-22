package factexporter;

import ghidra.app.decompiler.*;
import ghidra.app.services.GraphDisplayBroker;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.FunctionPrototype;
import ghidra.program.model.pcode.*;
import ghidra.program.model.pcode.VarnodeAST;
import ghidra.util.Msg;

public class FunctionAnalyzer {
	
	private DecompInterface _decompInterface;
	private PluginTool _tool;
	private Listing _listing;
	
	public FunctionAnalyzer(Program program, PluginTool tool) 
	{
		_tool = tool;
		_decompInterface = new DecompInterface();
		_decompInterface.openProgram(program);
		_listing = program.getListing();
	}
	
	// Not able to create the visual graphs, for now
	public FunctionAnalyzer(Program program) 
	{
		_decompInterface = new DecompInterface();
		_decompInterface.openProgram(program);
		_listing = program.getListing();
	}
	
	public void findReturnsSelf()
	{
		var funcIter = _listing.getFunctions(true);
		while (funcIter.hasNext()) {	
			Function function = funcIter.next();
			if (function == null) {
				Msg.warn("GraphAST Error",
						"No Function at current location");
				return;
			}


			DecompileResults res = _decompInterface.decompileFunction(function, 30, null);
			HighFunction high = res.getHighFunction();
	
			FunctionPrototype funcPrototype = high.getFunctionPrototype();
			
			if (function.getThunkedFunction(true) == null) {
				if (funcPrototype.getNumParams() > 0) {
					HighSymbol firstParamaterSymbol = funcPrototype.getParam(0);

					HighVariable variable = firstParamaterSymbol.getHighVariable();
					VarnodeAST varNode = (VarnodeAST)variable.getRepresentative();
					PCodeDfgGraph graph;
					if (_tool != null) 
					{
						GraphDisplayBroker graphDisplayBroker = _tool.getService(GraphDisplayBroker.class);
						if (graphDisplayBroker == null) {
							Msg.showError(this, _tool.getToolFrame(), "GraphAST Error",
								"No graph display providers found: Please add a graph display provider to your tool");
							return;
						}
						graph = new PCodeDfgGraph(_tool, graphDisplayBroker, high);
					}
					else 
					{
						graph = new PCodeDfgGraph(high);
					}
					graph.buildGraph();
					graph.checkIfReturnsSelf(varNode);
				}
			}
		}
	}
}

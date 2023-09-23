package factexporter;

import ghidra.app.plugin.core.decompile.actions.PCodeDfgDisplayOptions;
import ghidra.app.plugin.core.decompile.actions.PCodeDfgGraphType;
import ghidra.app.services.GraphDisplayBroker;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;
import ghidra.service.graph.AttributedGraph;
import ghidra.service.graph.GraphDisplay;
import ghidra.service.graph.GraphDisplayOptions;
import ghidra.service.graph.GraphType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.GraphException;
import ghidra.util.task.TaskMonitor;

public class DataflowDisplayGraph extends DataflowGraph {
	
	private PluginTool tool;
	private GraphDisplayBroker graphService;
	
	public DataflowDisplayGraph(PluginTool tool,GraphDisplayBroker graphService, HighFunction highFunction) {
		super(highFunction);
		this.graphService = graphService;
		this.tool = tool;
	}
	
	protected void buildAndDisplayGraph(TaskMonitor monitor)
			throws GraphException, CancelledException {

		GraphType graphType = new PCodeDfgGraphType();
		Function func = hfunction.getFunction();
		graph = new AttributedGraph("Data Flow Graph", graphType);
		buildGraph();
		GraphDisplay graphDisplay = graphService.getDefaultGraphDisplay(false, monitor);
		GraphDisplayOptions displayOptions = new PCodeDfgDisplayOptions(tool);

		String description = "AST Data Flow Graph For " + func.getName();
		graphDisplay.setGraph(graph, displayOptions, description, false, monitor);

		// Install a handler so the selection/location will map
		graphDisplay.setGraphDisplayListener(new DataflowDisplayGraphListener(tool, graphDisplay,
			hfunction, func.getProgram()));
	}

}

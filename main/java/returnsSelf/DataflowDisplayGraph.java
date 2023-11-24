package returnsSelf;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.core.decompile.actions.PCodeDfgDisplayOptions;
import ghidra.app.plugin.core.decompile.actions.PCodeDfgGraphType;
import ghidra.app.services.GraphDisplayBroker;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.service.graph.AttributedGraph;
import ghidra.service.graph.GraphDisplay;
import ghidra.service.graph.GraphDisplayOptions;
import ghidra.service.graph.GraphType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.GraphException;
import ghidra.util.task.TaskMonitor;

public class DataflowDisplayGraph {
	
	private PluginTool tool;
	private GraphDisplayBroker graphService;
	private DataflowGraph dataflowGraph;
	private HighFunction highFunction;
	
	private DataflowDisplayGraph(PluginTool tool) {
		this.tool = tool;
		graphService = tool.getService(GraphDisplayBroker.class);
	}
	
	public DataflowDisplayGraph(PluginTool tool, HighFunction highFunction) {
		this(tool);
		this.highFunction = highFunction;
		dataflowGraph = new DataflowGraph(highFunction);
	}
	
	public DataflowDisplayGraph(PluginTool tool, Program program, String addressString) {
		this(tool);
		var address = program.getAddressFactory().getAddress(addressString);
		DecompInterface decompInterface = new DecompInterface();
		decompInterface.openProgram(program);
		Function function = program.getFunctionManager().getFunctionAt(address);
		DecompileResults res = decompInterface.decompileFunction(function, 30, null);
		highFunction = res.getHighFunction();
		dataflowGraph = new DataflowGraph(highFunction);
	}
	
	public void buildAndDisplayGraph()
			throws GraphException, CancelledException {
		var monitor = TaskMonitor.DUMMY;
		Function func = highFunction.getFunction();
		dataflowGraph.buildGraph();
		GraphDisplay graphDisplay = graphService.getDefaultGraphDisplay(false, monitor);
		GraphDisplayOptions displayOptions = new PCodeDfgDisplayOptions(tool);

		String description = "AST Data Flow Graph For " + func.getName();
		graphDisplay.setGraph(dataflowGraph.graph(), displayOptions, description, false, monitor);

		graphDisplay.setGraphDisplayListener(new DataflowDisplayGraphListener(tool, graphDisplay,
				highFunction, func.getProgram()));
	}

}

package factexporter;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.services.GraphDisplayBroker;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.FunctionPrototype;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighParam;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.pcode.VarnodeAST;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.GraphException;
import ghidra.util.task.TaskMonitor;

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
	
	private ArrayList<String> notWorkingFunctions = new ArrayList<String>() 
	{{
		add("__FindPESection");
		//add("thunk_FUN_00411be0"); // to many vertices
		add("_RTC_GetSrcLine");
		//add("FUN_00411be0");
		add("@_RTC_AllocaHelper@12");
		add("_getMemBlockDataString");
		add("__RTC_UninitUse");
		//add("Unwind@00415a50");
	}}; 
	
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

			if (notWorkingFunctions.contains(function.getName())) {continue;}
			GraphDisplayBroker graphDisplayBroker = _tool.getService(GraphDisplayBroker.class);
			if (graphDisplayBroker == null) {
				Msg.showError(this, _tool.getToolFrame(), "GraphAST Error",
					"No graph display providers found: Please add a graph display provider to your tool");
				return;
			}
			DecompileResults res = _decompInterface.decompileFunction(function, 30, null);
			HighFunction high = res.getHighFunction();
	
			FunctionPrototype funcPrototype = high.getFunctionPrototype();
			
			//if (function.getName().equals("Unwind@00415a50")) {
				if (funcPrototype.getNumParams() > 0) {
					HighSymbol firstParamaterSymbol = funcPrototype.getParam(0);

					HighVariable variable = firstParamaterSymbol.getHighVariable();
					VarnodeAST varNode = (VarnodeAST)variable.getRepresentative();
			
					PCodeDfgGraph graph = new PCodeDfgGraph(_tool, graphDisplayBroker, high);
					graph.buildGraph();
					graph.checkIfReturnsSelf(varNode);
					
//					try {
//						graph.buildAndDisplayGraph(TaskMonitor.DUMMY);
//					} catch (GraphException e) {
//						// TODO Auto-generated catch block
//						e.printStackTrace();
//					} catch (CancelledException e) {
//						// TODO Auto-generated catch block
//						e.printStackTrace();
//					}				
//					graph.checkIfReturnsSelf(varNode);
				}
			//}

		}
	}
}

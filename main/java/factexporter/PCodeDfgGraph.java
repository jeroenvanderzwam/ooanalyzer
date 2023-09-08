package factexporter;

import static ghidra.app.plugin.core.decompile.actions.PCodeDfgDisplayOptions.*;

import java.util.*;

import com.kenai.jffi.Array;

import ghidra.app.plugin.core.decompile.actions.PCodeDfgDisplayOptions;
import ghidra.app.plugin.core.decompile.actions.PCodeDfgGraphType;
import ghidra.app.services.GraphDisplayBroker;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.*;
import ghidra.service.graph.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.GraphException;
import ghidra.util.task.TaskMonitor;

public class PCodeDfgGraph {

	private GraphDisplayBroker graphService;
	protected HighFunction hfunction;
	private AttributedGraph graph;
	private PluginTool tool;
	private HashMap<Integer, AttributedVertex> vertices = new HashMap<>();
	private HashMap<Integer, AttributedVertex> returnVertices = new HashMap<>();
	
	public PCodeDfgGraph(PluginTool tool,GraphDisplayBroker graphService, HighFunction highFunction) {
		hfunction = highFunction;
		this.graphService = graphService;
		this.tool = tool;
		GraphType graphType = new PCodeDfgGraphType();
		graph = new AttributedGraph("Data Flow Graph", graphType);
	}
	
	private List<AttributedVertex> hasPathToReturn(AttributedVertex vertex, AttributedVertex possibleReturnVertex) {
		List<List<AttributedVertex>> frontier = new ArrayList<>();
		frontier.add(new ArrayList<AttributedVertex>() {{ add(vertex); }});
		while (!frontier.isEmpty()) {
			var nextVertexList = frontier.remove(0);
			var nextVertex= nextVertexList.get(nextVertexList.size() - 1);
			if (nextVertex == null) { continue; }
			if (nextVertex.equals(possibleReturnVertex)) {
				return nextVertexList;
			}
			for (var edge : graph.outgoingEdgesOf(nextVertex)) {
				var newVertexList = new ArrayList<>(nextVertexList);
				newVertexList.add(graph.getEdgeTarget(edge));
				frontier.add(newVertexList);
			}
		}
		return null;
	}
	
	private ArrayList<String> allowedOperations = new ArrayList<String>() 
	{{
		add("STACK");
		add("UNIQUE");
		add("INDIRECT (CALL)");
		add("COPY");
		add("MULTIEQUAL");
		add("VARIABLE");
		add("RETURN");
		add("PIECE");
		add("CAST");
	}}; // CALL, LOAD ram, PTRADD
		
	private ArrayList<String> registers = new ArrayList<String>() 
	{{
		add("ECX");
		add("EAX");
	}};
	
	public boolean pathHasOnlyAllowedOperations(List<AttributedVertex> path) 
	{
		for (var vertexOnPath : path) {
			var name = vertexOnPath.getAttribute("Name");
			if (name.contains(":")) {
				name = name.split(":")[0];
			}
			if (name.contains("[")) {
				name = name.split("\\[")[0];
			}
			if (!allowedOperations.contains(name.toUpperCase()) && !registers.contains(name.toUpperCase())) {
				return false;
			}
		}
		return true;
	}
	
	
	public void checkIfReturnsSelf(VarnodeAST param) 
	{
		var vertex = vertices.get(param.getUniqueId());
		for (var entry : returnVertices.entrySet()) {
			AttributedVertex possibleReturnVertex = entry.getValue();
			List<AttributedVertex> path = hasPathToReturn(vertex, possibleReturnVertex);
			if (path != null) {
				if (pathHasOnlyAllowedOperations(path) ) {
					Msg.info(this, String.format("%s Allowed path found from %s --> %s",hfunction.getFunction().getName(), vertex, possibleReturnVertex));
					Msg.info(this, path);
					return;
				}
				
			}
		}
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
//		graphDisplay.setGraphDisplayListener(new PCodeDfgDisplayListener(tool, graphDisplay,
//			hfunction, func.getProgram()));
	}
	
	protected void buildGraph() {
		Iterator<PcodeOpAST> opiter = getPcodeOpIterator();
		while (opiter.hasNext()) {
			PcodeOpAST op = opiter.next();
			AttributedVertex o = createOpVertex(op);
			for (int i = 0; i < op.getNumInputs(); ++i) {
				int opcode = op.getOpcode();
				
				if ((i == 0) && ((opcode == PcodeOp.LOAD) || (opcode == PcodeOp.STORE))) {
					continue;
				}
				if ((i == 1) && (opcode == PcodeOp.INDIRECT)) {
					continue;
				}
				VarnodeAST vn = (VarnodeAST) op.getInput(i);
				if (vn != null) {
					AttributedVertex v = getVarnodeVertex(vertices, vn);
					createEdge(v, o);
					if (opcode == PcodeOp.RETURN) {
						returnVertices.put(vn.getUniqueId(), o);
					}
				}
			}
			VarnodeAST outvn = (VarnodeAST) op.getOutput();
			if (outvn != null) {
				AttributedVertex outv = getVarnodeVertex(vertices, outvn);
				if (outv != null) {
					createEdge(o, outv);
				}
			}
		}
	}
	
	private String getVarnodeKey(VarnodeAST vn) {
		PcodeOp op = vn.getDef();
		String id;
		if (op != null) {
			id = op.getSeqnum().getTarget().toString(true) + " v " +
				Integer.toString(vn.getUniqueId());
		}
		else {
			id = "i v " + Integer.toString(vn.getUniqueId());
		}
		return id;
	}

	protected AttributedVertex createVarnodeVertex(VarnodeAST vn) {
		String name = vn.getAddress().toString(true);
		String id = getVarnodeKey(vn);
		String vertexType = PCodeDfgGraphType.DEFAULT_VERTEX;
		if (vn.isConstant()) {
			vertexType = PCodeDfgGraphType.CONSTANT;
		}
		else if (vn.isRegister()) {
			vertexType = PCodeDfgGraphType.REGISTER;
			Register reg =
				hfunction.getFunction().getProgram().getRegister(vn.getAddress(), vn.getSize());
			if (reg != null) {
				name = reg.getName();
			}
		}
		else if (vn.isUnique()) {
			vertexType = PCodeDfgGraphType.UNIQUE;
		}
		else if (vn.isPersistent()) {
			vertexType = PCodeDfgGraphType.PERSISTENT;
		}
		else if (vn.isAddrTied()) {
			vertexType = PCodeDfgGraphType.ADDRESS_TIED;
		}
		AttributedVertex vert = graph.addVertex(id, name);
		vert.setVertexType(vertexType);
		// if it is an input override the shape to be a triangle
		if (vn.isInput()) {
			vert.setAttribute(SHAPE_ATTRIBUTE, VertexShape.TRIANGLE_DOWN.getName());
		}
		return vert;
	}

	protected AttributedVertex getVarnodeVertex(Map<Integer, AttributedVertex> vertices,
			VarnodeAST vn) {
		AttributedVertex res;
		res = vertices.get(vn.getUniqueId());
		if (res == null) {
			res = createVarnodeVertex(vn);
			vertices.put(vn.getUniqueId(), res);
		}
		return res;
	}

	protected AttributedEdge createEdge(AttributedVertex in, AttributedVertex out) {
		AttributedEdge newEdge = graph.addEdge(in, out);
		newEdge.setEdgeType(PCodeDfgGraphType.DEFAULT_EDGE);
		return newEdge;
	}

	protected AttributedVertex createOpVertex(PcodeOpAST op) {
		String name = op.getMnemonic();
		String id = getOpKey(op);
		int opcode = op.getOpcode();
		if ((opcode == PcodeOp.LOAD) || (opcode == PcodeOp.STORE)) {
			Varnode vn = op.getInput(0);
			AddressSpace addrspace =
				hfunction.getFunction()
						.getProgram()
						.getAddressFactory()
						.getAddressSpace((int) vn.getOffset());
			name += ' ' + addrspace.getName();
		}
		else if (opcode == PcodeOp.INDIRECT) {
			Varnode vn = op.getInput(1);
			if (vn != null) {
				PcodeOp indOp = hfunction.getOpRef((int) vn.getOffset());
				if (indOp != null) {
					name += " (" + indOp.getMnemonic() + ')';
				}
			}
		}
		AttributedVertex vert = graph.addVertex(id, name);
		vert.setVertexType(PCodeDfgGraphType.OP);
		return vert;
	}

	protected Iterator<PcodeOpAST> getPcodeOpIterator() {
		Iterator<PcodeOpAST> opiter = hfunction.getPcodeOps();
		return opiter;
	}

	private String getOpKey(PcodeOpAST op) {
		SequenceNumber sq = op.getSeqnum();
		String id =
			sq.getTarget().toString(true) + " o " + Integer.toString(op.getSeqnum().getTime());
		return id;
	}
}
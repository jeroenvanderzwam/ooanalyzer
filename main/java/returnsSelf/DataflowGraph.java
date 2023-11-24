package returnsSelf;

import static ghidra.app.plugin.core.decompile.actions.PCodeDfgDisplayOptions.*;

import java.util.*;

import ghidra.app.plugin.core.decompile.actions.*;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.pcode.*;
import ghidra.service.graph.*;
import ghidra.util.Msg;

public class DataflowGraph {
	protected HighFunction hfunction;
	protected AttributedGraph graph;

	private HashMap<Integer, AttributedVertex> vertices = new HashMap<>();
	private HashMap<Integer, AttributedVertex> returnVertices = new HashMap<>();

	public DataflowGraph(HighFunction highFunction) {
		hfunction = highFunction;
		GraphType graphType = new PCodeDfgGraphType();
		graph = new AttributedGraph("Data Flow Graph", graphType);
	}
	
	public AttributedGraph graph() {
		return graph;
	}

	public void buildGraph() {
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

	public void checkIfReturnsSelf(VarnodeAST param) {
		var vertex = vertices.get(param.getUniqueId());
		for (var entry : returnVertices.entrySet()) {
			AttributedVertex possibleReturnVertex = entry.getValue();
			List<AttributedVertex> path = hasValidPathToReturn(vertex, possibleReturnVertex);
			if (path != null) {
				Msg.out(String.format("returnsSelf(%s)", hfunction.getFunction().getEntryPoint()));
				return;
			}
		}
	}

	private List<AttributedVertex> hasValidPathToReturn(AttributedVertex vertex,
			AttributedVertex possibleReturnVertex) {
		List<List<AttributedVertex>> frontier = new ArrayList<>();
		frontier.add(new ArrayList<AttributedVertex>() {
			{
				add(vertex);
			}
		});
		while (!frontier.isEmpty()) {
			var nextVertexList = frontier.remove(0);
			var nextVertex = nextVertexList.get(nextVertexList.size() - 1);
			if (nextVertex == null) {
				continue;
			}
			var previousVertexes = nextVertexList.subList(0, nextVertexList.size() - 1);
			if (previousVertexes.contains(nextVertex)) {
				continue;
			}
			if (!operationIsAllowed(nextVertex)) {
				continue;
			}
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

	private ArrayList<String> allowedOperations = new ArrayList<String>() {
		{
			add("STACK");
			add("UNIQUE");
			add("INDIRECT (CALL)");
			add("COPY");
			add("MULTIEQUAL");
			add("VARIABLE");
			add("RETURN");
			add("PIECE");
			add("CAST");
		}
	};

	private boolean isRegister(AttributedVertex vertex) {
		var vertexType = vertex.getAttribute("VertexType");
		if (vertexType == "Register") {
			return true;
		}
		return false;
	}

	private boolean isAllowedOperation(AttributedVertex vertex) {
		var name = vertex.getAttribute("Name");
		if (name.contains(":")) {
			name = name.split(":")[0];
		}
		if (name.contains("[")) {
			name = name.split("\\[")[0];
		}
		if (allowedOperations.contains(name.toUpperCase())) {
			return true;
		}
		return false;
	}

	private boolean operationIsAllowed(AttributedVertex vertex) {
		if (isRegister(vertex)) {
			return true;
		}
		if (isAllowedOperation(vertex)) {
			return true;
		}
		return false;
	}

	private String getVarnodeKey(VarnodeAST vn) {
		PcodeOp op = vn.getDef();
		String id;
		if (op != null) {
			id = op.getSeqnum().getTarget().toString(true) + " v " + Integer.toString(vn.getUniqueId());
		} else {
			id = "i v " + Integer.toString(vn.getUniqueId());
		}
		return id;
	}

	private AttributedVertex createVarnodeVertex(VarnodeAST vn) {
		String name = vn.getAddress().toString(true);
		String id = getVarnodeKey(vn);
		String vertexType = PCodeDfgGraphType.DEFAULT_VERTEX;
		if (vn.isConstant()) {
			vertexType = PCodeDfgGraphType.CONSTANT;
		} else if (vn.isRegister()) {
			vertexType = PCodeDfgGraphType.REGISTER;
			Register reg = hfunction.getFunction().getProgram().getRegister(vn.getAddress(), vn.getSize());
			if (reg != null) {
				name = reg.getName();
			}
		} else if (vn.isUnique()) {
			vertexType = PCodeDfgGraphType.UNIQUE;
		} else if (vn.isPersistent()) {
			vertexType = PCodeDfgGraphType.PERSISTENT;
		} else if (vn.isAddrTied()) {
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

	private AttributedVertex getVarnodeVertex(Map<Integer, AttributedVertex> vertices, VarnodeAST vn) {
		AttributedVertex res;
		res = vertices.get(vn.getUniqueId());
		if (res == null) {
			res = createVarnodeVertex(vn);
			vertices.put(vn.getUniqueId(), res);
		}
		return res;
	}

	private AttributedEdge createEdge(AttributedVertex in, AttributedVertex out) {
		AttributedEdge newEdge = graph.addEdge(in, out);
		newEdge.setEdgeType(PCodeDfgGraphType.DEFAULT_EDGE);
		return newEdge;
	}

	private AttributedVertex createOpVertex(PcodeOpAST op) {
		String name = op.getMnemonic();
		String id = getOpKey(op);
		int opcode = op.getOpcode();
		if ((opcode == PcodeOp.LOAD) || (opcode == PcodeOp.STORE)) {
			Varnode vn = op.getInput(0);
			AddressSpace addrspace = hfunction.getFunction().getProgram().getAddressFactory()
					.getAddressSpace((int) vn.getOffset());
			name += ' ' + addrspace.getName();
		} else if (opcode == PcodeOp.INDIRECT) {
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

	private Iterator<PcodeOpAST> getPcodeOpIterator() {
		Iterator<PcodeOpAST> opiter = hfunction.getPcodeOps();
		return opiter;
	}

	private String getOpKey(PcodeOpAST op) {
		SequenceNumber sq = op.getSeqnum();
		String id = sq.getTarget().toString(true) + " o " + Integer.toString(op.getSeqnum().getTime());
		return id;
	}
}

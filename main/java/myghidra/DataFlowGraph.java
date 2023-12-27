package myghidra;

import static ghidra.app.plugin.core.decompile.actions.PCodeDfgDisplayOptions.SHAPE_ATTRIBUTE;

import java.util.HashMap;
import java.util.Iterator;

import ghidra.app.plugin.core.decompile.actions.PCodeDfgGraphType;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.SequenceNumber;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.pcode.VarnodeAST;
import ghidra.service.graph.AttributedEdge;
import ghidra.service.graph.AttributedGraph;
import ghidra.service.graph.AttributedVertex;
import ghidra.service.graph.GraphType;
import ghidra.service.graph.VertexShape;

public class DataFlowGraph 
{
	private HashMap<Integer, AttributedVertex> vertices = new HashMap<>();
	private HashMap<Integer, AttributedVertex> returnVertices = new HashMap<>();
	protected AttributedGraph graph;
	protected HighFunction hfunction;
	
	public DataFlowGraph(HighFunction hfunction) 
	{
		GraphType graphType = new PCodeDfgGraphType();
		graph = new AttributedGraph("Data Flow Graph", graphType);
		this.hfunction = hfunction;
	}
	
	public HashMap<Integer, AttributedVertex> vertices() 
	{
		return vertices;
	}
	
	public HashMap<Integer, AttributedVertex> returnVertices() 
	{
		return returnVertices;
	}
	
	public AttributedGraph graph() 
	{
		return graph;
	}
	
	public void buildGraph() 
	{
		Iterator<PcodeOpAST> opiter = hfunction.getPcodeOps();
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
					AttributedVertex v = getVarnodeVertex(vn);
					createEdge(v, o);
					if (opcode == PcodeOp.RETURN) {
						returnVertices.put(vn.getUniqueId(), o);
					}
				}
			}
			VarnodeAST outvn = (VarnodeAST) op.getOutput();
			if (outvn != null) {
				AttributedVertex outv = getVarnodeVertex(outvn);
				if (outv != null) {
					createEdge(o, outv);
				}
			}
		}
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
	
	private AttributedVertex getVarnodeVertex(VarnodeAST vn) {
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

	private String getOpKey(PcodeOpAST op) {
		SequenceNumber sq = op.getSeqnum();
		String id = sq.getTarget().toString(true) + " o " + Integer.toString(op.getSeqnum().getTime());
		return id;
	}

}

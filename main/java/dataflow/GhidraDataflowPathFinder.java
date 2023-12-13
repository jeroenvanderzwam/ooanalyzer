package dataflow;

import java.util.*;

import ghidra.program.model.pcode.*;
import ghidra.service.graph.*;

public class GhidraDataflowPathFinder {
	private DataFlowGraph dataFlowGraph;
	
	private List<AttributedVertex> path;

	public GhidraDataflowPathFinder(HighFunction highFunction) 
	{
		dataFlowGraph = new DataFlowGraph(highFunction);
	}
	
	public void buildGraph() 
	{
		dataFlowGraph.buildGraph();
	}

	public boolean pathFromParamToReturn(VarnodeAST param) {
		var vertex = dataFlowGraph.vertices().get(param.getUniqueId());
		for (var entry : dataFlowGraph.returnVertices().entrySet()) {
			AttributedVertex possibleReturnVertex = entry.getValue();
			path = hasValidPathToReturn(vertex, possibleReturnVertex);
			if (path != null) {
				return true;
			}
		}
		return false;
	}

	private List<AttributedVertex> hasValidPathToReturn(AttributedVertex vertex, AttributedVertex possibleReturnVertex) {
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
			for (var edge : dataFlowGraph.graph().outgoingEdgesOf(nextVertex)) {
				var newVertexList = new ArrayList<>(nextVertexList);
				newVertexList.add(dataFlowGraph.graph().getEdgeTarget(edge));
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
}

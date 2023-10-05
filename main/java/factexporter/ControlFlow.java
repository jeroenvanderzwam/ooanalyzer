package factexporter;

import ghidra.graph.GDirectedGraph;
import ghidra.graph.GraphFactory;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.*;
import ghidra.program.model.block.graph.*;
import ghidra.program.model.listing.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class ControlFlow {

		protected GDirectedGraph<CodeBlockVertex, CodeBlockEdge> _cfg;
		protected Program _program;
		
		public ControlFlow(Program program) {
			_program = program;
			_cfg = GraphFactory.createDirectedGraph();
		}
		
		public GDirectedGraph<CodeBlockVertex, CodeBlockEdge> CreateGraph(Function function) {
			BasicBlockModel basicBlockModel = new BasicBlockModel(_program);
			AddressSetView addrSet = function.getBody();
			try {
				CodeBlockIterator codeBlockIter = basicBlockModel.getCodeBlocksContaining(addrSet, TaskMonitor.DUMMY);
			
				while (codeBlockIter.hasNext()) {
					CodeBlock block = codeBlockIter.next();
					CodeBlockReferenceIterator dstBlocks = block.getDestinations(TaskMonitor.DUMMY);
					
					while (dstBlocks.hasNext()) {
						this.addEdge(dstBlocks.next());
					}
					
				}
			} catch (CancelledException e) {
				e.printStackTrace();
			}
			return _cfg;
		}
		
		public void addEdge(CodeBlockReference codeBlockRef) {
			CodeBlockEdge edge = new CodeBlockEdge(new CodeBlockVertex(codeBlockRef.getSourceBlock()), new CodeBlockVertex(codeBlockRef.getDestinationBlock()));
			this._cfg.addEdge(edge);
		}
		
		public void addEdge(CodeBlock srcBlock, CodeBlock dstBlock) {
			CodeBlockEdge edge = new CodeBlockEdge(new CodeBlockVertex(srcBlock), new CodeBlockVertex(dstBlock));
			this._cfg.addEdge(edge);
		}
}
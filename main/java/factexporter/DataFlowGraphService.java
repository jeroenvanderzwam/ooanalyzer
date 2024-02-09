package factexporter;

import factexporter.datastructures.Function;
import factexporter.datastructures.Value;

public interface DataFlowGraphService 
{
	void buildGraph(Function functionName);
	boolean pathFromParamToReturn(Value param);
}

package factexporter;

import factexporter.datastructures.Func;
import factexporter.datastructures.Parameter;

public interface DataFlowGraphService 
{
	void buildGraph(Func functionName);
	boolean pathFromParamToReturn(Parameter param);
}

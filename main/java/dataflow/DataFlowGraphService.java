package dataflow;

import sourcecode.Function;
import sourcecode.Parameter;

public interface DataFlowGraphService 
{
	void buildGraph(Function functionName);
	boolean pathFromParamToReturn(Parameter param);
}

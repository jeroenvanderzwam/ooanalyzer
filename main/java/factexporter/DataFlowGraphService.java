package factexporter;

import sourcecode.Func;
import sourcecode.Parameter;

public interface DataFlowGraphService 
{
	void buildGraph(Func functionName);
	boolean pathFromParamToReturn(Parameter param);
}

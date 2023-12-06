package factexporter;

public interface DataFlowGraphService 
{
	void buildGraph(Function functionName);
	boolean pathFromParamToReturn(Parameter param);
}

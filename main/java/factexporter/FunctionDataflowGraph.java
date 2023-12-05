package factexporter;

public interface FunctionDataflowGraph 
{
	void build(Function function);
	void pathFromParamToReturn(Parameter param);
}

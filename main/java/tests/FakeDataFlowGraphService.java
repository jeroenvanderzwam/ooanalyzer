package tests;

import factexporter.DataFlowGraphService;
import sourcecode.Func;
import sourcecode.Parameter;

public class FakeDataFlowGraphService implements DataFlowGraphService {

	@Override
	public void buildGraph(Func functionName) 
	{

	}

	@Override
	public boolean pathFromParamToReturn(Parameter param) {
		return true;
	}

}

package tests;

import dataflow.DataFlowGraphService;
import sourcecode.Function;
import sourcecode.Parameter;

public class MockDataFlowGraphService implements DataFlowGraphService {

	@Override
	public void buildGraph(Function functionName) 
	{

	}

	@Override
	public boolean pathFromParamToReturn(Parameter param) {
		return true;
	}

}

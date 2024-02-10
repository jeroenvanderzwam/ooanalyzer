package tests;

import factexporter.DataFlowGraphService;
import factexporter.datastructures.Function;
import factexporter.datastructures.Value;

public class FakeDataFlowGraphService implements DataFlowGraphService {

	@Override
	public void buildGraph(Function functionName) 
	{

	}

	@Override
	public boolean pathFromParamToReturn(Value param) {
		return true;
	}

}

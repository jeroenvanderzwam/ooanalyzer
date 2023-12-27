package tests;

import factexporter.DataFlowGraphService;
import factexporter.datastructures.Func;
import factexporter.datastructures.Parameter;

class FakeDataFlowGraphService implements DataFlowGraphService {

	@Override
	public void buildGraph(Func functionName) 
	{

	}

	@Override
	public boolean pathFromParamToReturn(Parameter param) {
		return true;
	}

}

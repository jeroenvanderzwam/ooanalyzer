package tests;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.Test;

import factexporter.facts.FactFactory;

public class ReturnsSelfTest 
{
	FakeDecompilationService _service;
	FakeDataFlowGraphService _graph;
	ArrayListFile _file;
	
	@Before
	public void setUp() 
	{
		_service = new FakeDecompilationService();
		_service.initialize();
		_graph = new FakeDataFlowGraphService();
		_file = new ArrayListFile();
		var factFactory = new FactFactory();
		factFactory.createReturnsSelf(_service, _graph).createFacts(_file);
	}
	
	@Test
	public void testValidReturnsSelf() 
	{
		assertTrue(_file.read().get(0).equals("returnsSelf(00000001)."));
	}
	
	@Test
	public void testPassedOnStackSoNoReturnsSelf() 
	{
		assertFalse(_file.read().contains("returnsSelf(00000002)."));
	}
	
	@Test
	public void testThunkFunctionSoNoReturnsSelf() 
	{
		assertFalse(_file.read().contains("returnsSelf(00000003)."));
	}
	
	@Test
	public void testNoParametersSoNoReturnsSelf()
	{
		assertFalse(_file.read().contains("returnsSelf(00000003)."));
	}

}

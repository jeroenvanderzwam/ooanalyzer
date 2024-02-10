package tests.facts;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;

import org.junit.*;

import factexporter.datastructures.*;
import factexporter.facts.*;
import tests.FakeDataFlowGraphService;

public class ReturnsSelfFactTest extends FactTest
{
	private FakeDataFlowGraphService graph = new FakeDataFlowGraphService();
	private Fact returnsSelf;
	
	@Before
	public void setUp() {
		service.initialize();
		file.open();
		returnsSelf = new FactFactory().createReturnsSelf(service, graph);
	}
	
	@Test
	public void testValidReturnsSelf() {
		service.addFunction(Function.createFunction(funcAddress, funcName, 
				new ArrayList<Value>(){{ add(Value.createParameter(paramName, 4, 0, ecxRegister)); }}, 
				thisCallConvention, emptyCallInstructions));
		returnsSelf.createFacts(file);
		assertEquals("returnsSelf(%s).".formatted(funcAddress), file.read().get(0));
	}
	
	@Test
	public void testPassedOnStackSoNoReturnsSelf() {
		service.addFunction(Function.createFunction(funcAddress, funcName, 
				new ArrayList<Value>(){{ add(Value.createParameter(paramName, 4, 0, Storage.createStack(0))); }}, 
				fastCallConvention, emptyCallInstructions));
		returnsSelf.createFacts(file);
		
		assertTrue(file.read().isEmpty());
	}
	
	@Test
	public void testThunkFunctionSoNoReturnsSelf() {
		service.addFunction(Function.createThunkFunction(funcAddress, funcName, 
				new ArrayList<Value>(){{ add(Value.createParameter(paramName, 4, 0, ecxRegister)); }}, 
				fastCallConvention, emptyCallInstructions));
		returnsSelf.createFacts(file);
		
		assertTrue(file.read().isEmpty());
	}
	
	@Test
	public void testNoParametersSoNoReturnsSelf() {
		service.addFunction(Function.createFunction(funcAddress, funcName, new ArrayList<Value>(), 
				fastCallConvention, emptyCallInstructions));
		returnsSelf.createFacts(file);
		
		assertTrue(file.read().isEmpty());
	}
	
	@Test
	public void testParameterNotPassedInECX() {
		service.addFunction(Function.createFunction(funcAddress, funcName, 
				new ArrayList<Value>(){{ add(Value.createParameter(paramName, 4, 0, Storage.createRegister("EAX"))); }}, 
				thisCallConvention, emptyCallInstructions));
		returnsSelf.createFacts(file);
		
		assertTrue(file.read().isEmpty());
	}

}

package tests.facts;

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;

import org.junit.Before;
import org.junit.Test;

import factexporter.datastructures.*;
import factexporter.facts.*;

public class CallParameterFactTest extends FactTest {
	private Fact callParameter;
	
	@Before
	public void setUp() {
		service.initialize();
		file.open();
		callParameter = new FactFactory().createCallParameter(service);
	}
	
	@Test
	public void testValidCallParameterInRegister() {
		service.addFunction(Function.createFunction("2001", "FUN_2001", new ArrayList<Value>() 
		{{
			add(Value.createParameter("param1", 4, 0, ecxRegister));
		}}, fastCallConvention, emptyCallInstructions));
		
		var instructionAddress = "1001";
		var argName = "local_01";
		service.addFunction(Function.createFunction(funcAddress, funcName, emptyParameters, fastCallConvention, 
				new ArrayList<FunctionCallInstruction>() 
		{{
			add(new FunctionCallInstruction(instructionAddress, "2001", new ArrayList<Value>() 
				{{ add(Value.createVariable(argName, 4, Storage.createStack(0))); }}, 
				Value.createOtherValue()));
		}}));
		callParameter.createFacts(file);
		
		assertEquals("callParameter(%s, %s, %s, %s)".formatted(instructionAddress, funcAddress, "ECX", argName),
				file.read().get(0));
	}

	@Test
	public void testValidCallParamaterOnStack() {

	}
}

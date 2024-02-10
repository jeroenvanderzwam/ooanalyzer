package tests.facts;

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;

import org.junit.Before;
import org.junit.Test;

import factexporter.datastructures.*;
import factexporter.facts.*;

public class CallParameterFactTest extends FactTest {
	private Fact callParameter;
	private String instructionAddress = "1001";
	private String argName = "local_01";
	
	@Before
	public void setUp() {
		service.initialize();
		file.open();
		callParameter = new FactFactory().createCallParameter(service);
	}
	
	@Test
	public void testValidCallParameterInRegister() {
		addCalleeFunction(ecxRegister);
		addFunctionWithCallInstruction();
		
		callParameter.createFacts(file);
		
		assertEquals("callParameter(%s, %s, %s, %s)".formatted(instructionAddress, funcAddress, "ECX", argName),
				file.read().get(0));
	}

	@Test
	public void testValidCallParameterOnStack() {
		addCalleeFunction(Storage.createStack(4));
		addFunctionWithCallInstruction();
		
		callParameter.createFacts(file);
		
		assertEquals("callParameter(%s, %s, %s, %s)".formatted(instructionAddress, funcAddress, "1", argName),
				file.read().get(0));
	}
	
	private void addCalleeFunction(Storage storage) {
		service.addFunction(Function.createFunction("2001", "FUN_2001", new ArrayList<Value>() 
		{{
			add(Value.createParameter("param1", 4, 0, storage));
		}}, fastCallConvention, emptyCallInstructions));
	}
	
	private void addFunctionWithCallInstruction() {
		service.addFunction(Function.createFunction(funcAddress, funcName, emptyParameters, fastCallConvention, 
				new ArrayList<FunctionCallInstruction>() 
		{{
			add(new FunctionCallInstruction(instructionAddress, "2001", new ArrayList<Value>() 
				{{ add(Value.createVariable(argName, 4, Storage.createStack(0))); }}, 
				Value.createOtherValue()));
		}}));
	}
}

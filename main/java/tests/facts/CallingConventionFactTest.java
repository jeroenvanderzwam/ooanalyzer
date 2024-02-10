package tests.facts;

import static org.junit.Assert.assertEquals;

import org.junit.Before;
import org.junit.Test;

import factexporter.datastructures.*;
import factexporter.facts.*;

public class CallingConventionFactTest extends FactTest {
	private Fact callingConvention;

	@Before
	public void setUp() {
		service.initialize();
		file.open();
		callingConvention = new FactFactory().createCallingConvention(service);
	}
	
	@Test
	public void testCallingConventionFoundForFunction() {
		service.addFunction(Function.createFunction(funcAddress, funcName, emptyParameters, thisCallConvention, emptyCallInstructions));
		callingConvention.createFacts(file);
		assertEquals("callingConvention(%s, '%s')".formatted(funcAddress, thisCallConventionName),
				file.read().get(0));
	}
	
	@Test
	public void testNoCallingConventionFoundForFunction() {
		service.addFunction(Function.createFunction(funcAddress, fastCallConventionName, emptyParameters, 
				CallingConvention.createInvalidCallingConvention(), emptyCallInstructions));
		callingConvention.createFacts(file);
		assertEquals("callingConvention(%s, invalid)".formatted(funcAddress), 
				file.read().get(0));
	}
}

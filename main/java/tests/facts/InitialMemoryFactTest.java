package tests.facts;

import static org.junit.Assert.assertEquals;

import org.junit.Before;
import org.junit.Test;

import factexporter.facts.Fact;
import factexporter.facts.FactFactory;

public class InitialMemoryFactTest extends FactTest {

	private Fact initialMemory;

	@Before
	public void setUp() {
		service.initialize();
		file.open();
		initialMemory = new FactFactory().createInitialMemory(service);
	}
	
	@Test
	public void testValidInitialMemory() {
		var memoryAddress = "0001";
		var memoryValue = "0002";
		service.addInitialMemory(memoryAddress, memoryValue);
		initialMemory.createFacts(file);
		assertEquals("initialMemory(%s, %s)".formatted(memoryAddress, memoryValue), file.read().get(0));
	}
}

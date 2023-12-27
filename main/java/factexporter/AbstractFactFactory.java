package factexporter;

import java.util.List;

import factexporter.facts.Fact;

interface AbstractFactFactory {

	Fact createFact(String factType, List<String> args);
	List<String> availableFacts();
	List<String> availableArgs();
}

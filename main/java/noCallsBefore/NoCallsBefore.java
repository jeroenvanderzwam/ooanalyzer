package noCallsBefore;

import factexporter.DecompilationService;
import facts.Fact;

public class NoCallsBefore implements Fact {


	public void CreateFacts(DecompilationService service) {
		
		ThisPtrCalls thisPtrCalls = new ThisPtrCalls(service);
		thisPtrCalls.run();
	}
}

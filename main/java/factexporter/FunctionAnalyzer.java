package factexporter;

import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.data.GenericCallingConvention;
import ghidra.program.model.listing.Listing;
import ghidra.util.Msg;

public class FunctionAnalyzer {
	
	public void findConstructors(Listing listing, DecompInterface ifc) {
		
		var funcIter = listing.getFunctions(true);
		while(funcIter.hasNext()) {
			var func = funcIter.next();
			var funcName = func.getName();
			var signature = func.getSignature();
			var firstParameter = func.getParameter(0);
			if (signature != null && firstParameter != null) {
				var firstParameterName = firstParameter.getName();
				var genericCallingConvention = signature.getGenericCallingConvention();

				if (firstParameterName.equals("this") && genericCallingConvention.equals(GenericCallingConvention.thiscall)) {
					var decompiledFunction = ifc.decompileFunction(func, 0, null);
					var cCode = decompiledFunction.getCCodeMarkup();
					if (cCode.toString().endsWith("this;}")) {
						Msg.info(this, String.format("returnsSelf(%s)", funcName));
					}
				}
				
			}
		}
	}

}

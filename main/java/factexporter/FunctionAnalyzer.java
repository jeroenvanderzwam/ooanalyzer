package factexporter;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.data.GenericCallingConvention;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighParam;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.Msg;

public class FunctionAnalyzer {
	
	private FunctionManager _functionManager;
	private DecompInterface _decompInterface;
	private Listing _listing;
	
	public FunctionAnalyzer(Program program) 
	{
		_functionManager = program.getFunctionManager();
		_decompInterface = new DecompInterface();
		_decompInterface.openProgram(program);
		_listing = program.getListing();
	}
	
	public void findReturnsSelf() 
	{
		var funcIter = _listing.getFunctions(true);
		while(funcIter.hasNext()) {
			var func = funcIter.next();
			var signature = func.getSignature();
			var firstParameter = func.getParameter(0);
			if (signature != null && firstParameter != null) {
				var decompiledFunction = _decompInterface.decompileFunction(func, 0, null);

				var highFunction = decompiledFunction.getHighFunction();
				var localSymbolMap = highFunction.getLocalSymbolMap();
				var symbols = localSymbolMap.getSymbols();
				HighSymbol returnSymbol = null;
				while (symbols.hasNext()) 
				{
					returnSymbol = symbols.next();
				}
				var funcPrototype = highFunction.getFunctionPrototype();

				var firstParamaterSymbol = funcPrototype.getParam(0);
				
//				&& firstParamaterSymbol.isThisPointer() 
//				&& returnSymbol.isThisPointer()
//				&& !funcPrototype.hasNoReturn()
				if (returnSymbol.equals(firstParamaterSymbol) )
				{
					Msg.info(this, String.format("returnsSelf(%s)", func.getEntryPoint()));
				}				
			}
		}
	}
	
	List<String> noCallsBefore = new ArrayList<>();
	List<String> noCallsAfter = new ArrayList<>();

	public void findNoCallsBefore() 
	{
        var entryFunction = getEntryFunction();
        functionCrawlerNoCallsBefore(entryFunction);
        for (var functionName : noCallsBefore) {
        	Msg.info(this, String.format("noCallsBefore(%s)", functionName));
        }
        functionCrawlerNoCallsAfter(entryFunction);
        for (var functionName : noCallsAfter) {
        	Msg.info(this, String.format("noCallsAfter(%s)", functionName));
        }
	}
	
	public void functionCrawlerNoCallsAfter(Function function) 
	{
		String noCallsAfterInFunction = null;
        var decompileResults = _decompInterface.decompileFunction(function, 30, null);
        
        var pcodeOps = decompileResults.getHighFunction().getPcodeOps();
        
        while (pcodeOps.hasNext()) 
        {
        	var op = pcodeOps.next();
            if (op.getOpcode() == PcodeOp.CALL) {
                var calledFunctionAddress = op.getInput(0).getAddress();

                var calledFunction = _functionManager.getFunctionAt(calledFunctionAddress);
                if (calledFunction != null ) 
                {
                	var firstParameter = calledFunction.getParameter(0);
                	if (firstParameter != null && firstParameter.getName().equals("this")) 
                	{
                        var functionName = calledFunction.getName();
                        noCallsAfterInFunction = functionName;
                	}
                	functionCrawlerNoCallsAfter(calledFunction);
                }
            }
        }
        if (noCallsAfterInFunction != null) {
        	if (!noCallsAfter.contains(noCallsAfterInFunction)) {
        		noCallsAfter.add(noCallsAfterInFunction);
        	}
            noCallsAfterInFunction = null;
        }
	}
	
	public void functionCrawlerNoCallsBefore(Function function) 
	{
		String noCallsBeforeInFunction = null;
        var decompileResults = _decompInterface.decompileFunction(function, 30, null);
        
        var pcodeOps = decompileResults.getHighFunction().getPcodeOps();
        
        while (pcodeOps.hasNext()) 
        {
        	var op = pcodeOps.next();
            if (op.getOpcode() == PcodeOp.CALL) {
                var calledFunctionAddress = op.getInput(0).getAddress();

                var calledFunction = _functionManager.getFunctionAt(calledFunctionAddress);
                if (calledFunction != null ) 
                {
                	var firstParameter = calledFunction.getParameter(0);
                	if (firstParameter != null && firstParameter.getName().equals("this")) 
                	{
                        var functionName = calledFunction.getName();
                        if (noCallsBeforeInFunction == null) {
                        	noCallsBeforeInFunction = functionName;
                        }
                	}
                	functionCrawlerNoCallsBefore(calledFunction);
                }
            }
        }
        if (noCallsBeforeInFunction != null) {
        	if (!noCallsBefore.contains(noCallsBeforeInFunction)) {
                noCallsBefore.add(noCallsBeforeInFunction);
        	}
            noCallsBeforeInFunction = null;
        }

	}
	
	public Function getEntryFunction() 
	{
        var funcIter = _functionManager.getFunctions(true);

        for (var func : funcIter) 
        {
        	if (func.getName().equals("entry"))
        	{
        		return func;
        	}
        }
        return null;
	}

}

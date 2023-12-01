package facts;

import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.util.regex.Pattern;

import ghidra.app.decompiler.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.InvalidInputException;
import returnsSelf.DataflowGraph;

public class ReturnsSelf implements Fact {

	@Override
	public void CreateFacts(Program program) {
		var compilerSpec = program.getCompilerSpec();
		var callingConventions = compilerSpec.getCallingConventions();
 		var default_ = compilerSpec.getDefaultCallingConvention();
		var language = compilerSpec.getLanguage();
		var stackPointer = compilerSpec.getStackPointer();
		var properties = compilerSpec.getPropertyKeys();
		DecompInterface decompInterface = new DecompInterface();
		decompInterface.openProgram(program);
		var funcIter = program.getListing().getFunctions(true);
		var fileName = "C:/Users/jeroe/Downloads/Facts/Ghidra/" + program.getDomainFile().getName().split(Pattern.quote("."))[0] + ".ghidrafacts";
		PrintWriter file = null;
		try {
			file = new PrintWriter(fileName, "UTF-8");
		} catch (FileNotFoundException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (UnsupportedEncodingException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		while (funcIter.hasNext()) 
		{	
			Function function = funcIter.next();
			var callingConv = function.getCallingConvention();
			if (callingConv != null) {
				var firstArgLocation = callingConv.getArgLocation(0, function.getParameters(), null, program);
				var isContructor = callingConv.isConstructor();
				var hasThisPointer = callingConv.hasThisPointer();
				var potentialInput = callingConv.getPotentialInputRegisterStorage(program);
				var returnAddress = callingConv.getReturnAddress();
			}

			if (function.isThunk()) { continue; }
			DecompileResults res = decompInterface.decompileFunction(function, 30, null);
			HighFunction highFunction = res.getHighFunction();
			FunctionPrototype funcPrototype = highFunction.getFunctionPrototype();
			if (funcPrototype.getNumParams() == 0) { continue ;}
			HighSymbol firstParamaterSymbol = funcPrototype.getParam(0);
			HighVariable firstParamaterVariable = firstParamaterSymbol.getHighVariable();
			VarnodeAST firstParameterVarnode = (VarnodeAST)firstParamaterVariable.getRepresentative();
			if (firstParameterVarnode.isRegister()) {
				var register = firstParamaterSymbol.getStorage().getRegister();
				if (register.equals(program.getRegister("ECX"))) {
					DataflowGraph graph = new DataflowGraph(highFunction, file);
					graph.buildGraph();
					graph.checkIfReturnsSelf(firstParameterVarnode);
				}
			}

		}
		file.close();
	}
}

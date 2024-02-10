package tests.facts;

import java.util.ArrayList;

import factexporter.datastructures.CallingConvention;
import factexporter.datastructures.FunctionCallInstruction;
import factexporter.datastructures.Storage;
import factexporter.datastructures.Value;
import tests.ArrayListFile;
import tests.FakeDecompilationService;

public abstract class FactTest {
	protected static final String funcAddress = "0001";
	protected static final String funcName = "FUN_0001";
	protected static final String paramName = "param_1";
	protected static final String thisCallConventionName = "__thiscall__";
	protected static final String fastCallConventionName = "__fastcall__";
	
	protected CallingConvention thisCallConvention = new CallingConvention(thisCallConventionName);
	protected CallingConvention fastCallConvention = new CallingConvention(fastCallConventionName);
	protected Storage ecxRegister = Storage.createRegister("ECX");
	
	protected ArrayList<FunctionCallInstruction> emptyCallInstructions = new ArrayList<FunctionCallInstruction>();
	protected ArrayList<Value> emptyParameters = new ArrayList<Value>();
	
	protected ArrayListFile file = new ArrayListFile();
	protected FakeDecompilationService service = new FakeDecompilationService();
}

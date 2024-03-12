package factexporter.adapters;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import factexporter.DecompilationService;
import factexporter.datastructures.CompilerSpecification;
import factexporter.datastructures.Function;
import factexporter.facts.Memory;
import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.HighFunction;

public class GhidraDecompilationAdapter implements DecompilationService
{
	private Program program;
	private HashMap<String, HighFunction> _decompiledFunctions = new HashMap<String, HighFunction>();
	private ArrayList<Function> functions = new ArrayList<Function>();
	private ArrayList<Memory> memory = new ArrayList<Memory>();
	
	public GhidraDecompilationAdapter(Program prog) 
	{
		program = prog;
	}
	
	public void initialize() 
	{
		decompiledFunctions();
	}
	
	@Override
	public List<Function> functions() {
		if (functions.isEmpty()) {
			for (var highFunction : decompiledFunctions().values()) 
			{		
				var func = new FunctionBuilder().build(highFunction);
				addFunction(func);
			}
		}
		return functions;
	}

	@Override
	public CompilerSpecification compilerSpec() 
	{
		var compilerSpec = program.getCompilerSpec();
		return new CompilerSpecificationBuilder().build(compilerSpec);
	}

	@Override
	public String decompiledFileName() {
		return program.getDomainFile().getName();
	}
	
	public HashMap<String, HighFunction> decompiledFunctions() 
	{
		if (_decompiledFunctions.isEmpty()) 
		{
			var decompInterface = new DecompInterface();
			decompInterface.openProgram(program);
			var funcIter = program.getListing().getFunctions(true);
			while (funcIter.hasNext()) 
			{	
				var function = funcIter.next();
				var res = decompInterface.decompileFunction(function, 30, null);
				var highFunction = res.getHighFunction();
				_decompiledFunctions.put(function.getEntryPoint().toString(), highFunction);
			}
		}
		return _decompiledFunctions;
	}

	@Override
	public void addFunction(Function func) {
		functions.add(func);
	}

	@Override
	public List<Memory> memory() {
		if (memory.isEmpty()) {
			var ghidraMemory = program.getMemory();

			var memoryBlocks = ghidraMemory.getBlocks();

	        for (var memoryBlock : memoryBlocks) {
	        	var comment = memoryBlock.getComment();
	        	var name = memoryBlock.getName();
	        	var sourceName = memoryBlock.getSourceName();
	        	var sourceInfo = memoryBlock.getSourceInfos();
	        	var data = memoryBlock.getData();
	        	var start = memoryBlock.getStart();
	        	var end = memoryBlock.getEnd();

	            addInitialMemory("", "");
	        }
		}
		return memory;
	}

	@Override
	public void addInitialMemory(String address, String value) {
		memory.add(new Memory(address, value));
	}
}
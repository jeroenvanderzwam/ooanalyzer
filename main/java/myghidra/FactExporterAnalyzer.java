/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package myghidra;

import factexporter.DataFlowGraphService;
import factexporter.DecompilationService;
import factexporter.FactExporter;
import factexporter.adapters.GhidraDataFlowAdapter;
import factexporter.adapters.GhidraDecompilationAdapter;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this analyzer does.
 */
class FactExporterAnalyzer extends AbstractAnalyzer {

	public FactExporterAnalyzer() {

		// TODO: Name the analyzer and give it a description.

		super("Fact exporter Analyzer", "Creates facts for OOAnalyzer", AnalyzerType.BYTE_ANALYZER);
	}

	@Override
	public boolean getDefaultEnablement(Program program) {

		// TODO: Return true if analyzer should be enabled by default

		return true;
	}

	@Override
	public boolean canAnalyze(Program program) {

		// TODO: Examine 'program' to determine of this analyzer should analyze it.  Return true
		// if it can.

		return true;
	}

	@Override
	public void registerOptions(Options options, Program program) {

		// TODO: If this analyzer has custom options, register them here

		options.registerOption("Option name goes here", false, null,
			"Option description goes here");
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		// TODO: Perform analysis when things get added to the 'program'.  Return true if the
		// analysis succeeded.
		DecompilationService decompService = new GhidraDecompilationAdapter(program);
		decompService.initialize();
		
		//var service = (GhidraDecompilationAdapter)decompService;
		//var constructors = service.constructors();
		//var thisPointers = service.hasThisPointer();
		DataFlowGraphService graphService = new GhidraDataFlowAdapter((GhidraDecompilationAdapter)decompService);
		FactExporter factExporter = new FactExporter(decompService, graphService);
		factExporter.createFacts();

		return false;
	}
}

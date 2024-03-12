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

import java.io.File;
import java.util.regex.Pattern;

import com.kenai.jffi.ObjectParameterInfo.ObjectType;

import factexporter.FactExporter;
import factexporter.adapters.GhidraDataFlowAdapter;
import factexporter.adapters.GhidraDecompilationAdapter;
import factexporter.export.TextFile;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this analyzer does.
 */
public class FactExporterAnalyzer extends AbstractAnalyzer {
	
	private static final String FILEPATH_OPTION = "ExportPath";
	File exportFile;

	public FactExporterAnalyzer() {
		super("Fact exporter Analyzer", "Creates facts for OOAnalyzer", AnalyzerType.BYTE_ANALYZER);
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return true;
	}

	@Override
	public boolean canAnalyze(Program program) {
		return true;
	}

	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(FILEPATH_OPTION, OptionType.FILE_TYPE, new File(System.getProperty("user.home") + "\\Documents\\facts.ghidrafacts"), null, "File location where the export is placed.");
	}
	
	@Override
	public void optionsChanged(Options options, Program program) {
		exportFile = options.getFile(FILEPATH_OPTION, null);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		
		var decompService = new GhidraDecompilationAdapter(program);
		decompService.initialize();

		var graphService = new GhidraDataFlowAdapter(decompService);
		var factExporter = new FactExporter(decompService, graphService);

		var file = new TextFile(exportFile.getAbsolutePath());
		factExporter.createFacts(file);

		return false;
	}
}

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
package factexporter;

import java.awt.BorderLayout;
import java.util.Map;
import java.util.Map.Entry;

import javax.swing.*;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.block.FollowFlow;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.AcyclicCallGraphBuilder;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.graph.AbstractDependencyGraph;
import ghidra.util.task.TaskMonitor;
import resources.Icons;
import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.address.Address;

/**
 * TODO: Provide class-level documentation that describes what this plugin does.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = ExamplesPluginPackage.NAME,
	category = PluginCategoryNames.EXAMPLES,
	shortDescription = "Plugin short description goes here.",
	description = "Plugin long description goes here."
)
//@formatter:on
public class FactExporterPlugin extends ProgramPlugin {

	MyProvider provider;

	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public FactExporterPlugin(PluginTool tool) {
		super(tool);

		// TODO: Customize provider (or remove if a provider is not desired)
		String pluginName = getName();
		provider = new MyProvider(this, pluginName);

		// TODO: Customize help (or remove if help is not desired)
		String topicName = this.getClass().getPackage().getName();
		String anchorName = "HelpAnchor";
		provider.setHelpLocation(new HelpLocation(topicName, anchorName));
	}

	@Override
	public void init() {
		super.init();

		// TODO: Acquire services if necessary
	}
	
	@Override
	protected void programOpened(Program program) {
		// TODO Auto-generated method stub
		super.programOpened(program);
		
		AcyclicCallGraphBuilder builder = new AcyclicCallGraphBuilder(program, true);
		try {
			var graph = builder.getDependencyGraph(TaskMonitor.DUMMY);
			var nodes = graph.getNodeMap();
			for (var entry : nodes.entrySet()) 
			{
				var address = entry.getKey();
				var node = entry.getValue();
			}

			var independentValues = graph.getAllIndependentValues();
			var element = independentValues.toArray(new ghidra.program.model.address.Address[0])[0];
			var function = program.getListing().getFunctionAt(element);
			var dependentElements = graph.getDependentValues(element);
			if (graph.hasUnVisitedIndependentValues()) 
			{
				var unvisited = graph.getUnvisitedIndependentValues();
			}
			Msg.info(program, graph);
		} catch (CancelledException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
//		FollowFlow followFlow = new FollowFlow(program, new AddressSet(program, program.getMinAddress(), program.getMaxAddress()), null);
//		var iets = followFlow.getFlowToAddressSet(TaskMonitor.DUMMY);
//		var flow = followFlow.getFlowAddressSet(TaskMonitor.DUMMY);
		
		DecompInterface ifc = new DecompInterface();
		ifc.openProgram(program);
		FunctionAnalyzer funcAnalazer = new FunctionAnalyzer();
		funcAnalazer.findConstructors(program.getListing(), ifc);
		
	}

	// TODO: If provider is desired, it is recommended to move it to its own file
	private static class MyProvider extends ComponentProvider {

		private JPanel panel;
		private DockingAction action;

		public MyProvider(Plugin plugin, String owner) {
			super(plugin.getTool(), owner, owner);
			buildPanel();
			createActions();
		}

		// Customize GUI
		private void buildPanel() {
			panel = new JPanel(new BorderLayout());
			JTextArea textArea = new JTextArea(5, 25);
			textArea.setEditable(false);
			panel.add(new JScrollPane(textArea));
			setVisible(true);
		}

		// TODO: Customize actions
		private void createActions() {
			action = new DockingAction("My Action", getName()) {
				@Override
				public void actionPerformed(ActionContext context) {
					Msg.showInfo(getClass(), panel, "Custom Action", "Hello!");
				}
			};
			action.setToolBarData(new ToolBarData(Icons.ADD_ICON, null));
			action.setEnabled(true);
			action.markHelpUnnecessary();
			dockingTool.addLocalAction(this, action);
		}

		@Override
		public JComponent getComponent() {
			return panel;
		}
	}
}

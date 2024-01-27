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

import java.awt.BorderLayout;
import java.util.ArrayList;

import javax.swing.*;
import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.*;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.plugin.*;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.program.util.*;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.GraphException;
import resources.Icons;

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
	protected void locationChanged(ProgramLocation loc) {
	}

	@Override
	protected void highlightChanged(ProgramSelection hl) {
	}

	@Override
	protected void selectionChanged(ProgramSelection selection) {
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
		
//		var addressStrings = new ArrayList<String>() 
//		{{
//			add("140001e00"); 
//			add("140001e30"); 
//			add("140001e60"); 
//			add("140001e60"); 
//			add("140001ee0"); 
//			add("140001f70"); 
//			add("140002c80"); 
//			add("140002cd0"); 
//			add("140002d20");
//			add("140002d70");
//			add("140002dc0");
//			add("140002e00");
//			add("140002e70");
//		}};
//		
//		for(var addressString : addressStrings) {
//			DataflowDisplayGraph graph = new DataflowDisplayGraph(tool, program, addressString); 
//			try { 
//				graph.buildAndDisplayGraph(); 
//			}
//			catch (GraphException | CancelledException e) {
//				e.printStackTrace();
//			}
//		}

		 
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

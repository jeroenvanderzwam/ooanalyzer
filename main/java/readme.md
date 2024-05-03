# Overview of the packages:

**factexporter**: Contains the **FactExporter.java** class which is the most important entry point into the rest of the application. This is the class which constructs all the different facts.
- **adapters**: Adapters and builders necessary to convert Ghidra datastructures to our own datastructures.
- **datastructures**: The internal datastructures that our application uses (**File.java** is the interface each exporting class has to conform to).
- **export**: Exporting of the facts (for now only supports .txt files).
- **facts**: The different facts that we are working on at the moment (**Fact.java** is the interface each fact has to conform to).

**myghidra**: Ghidra classes that are necessary to get the data or knowledge out of ghidra into our own application

- **FactExporterPlugin.java**: Plugin that was each initially to create a simple plugin (is used for simple testing sometimes)
- **FactExporterAnalyzer.java**: Main entry point for Ghidra. This analyzer is loaded into Ghidra and connects to the FactExporter.java to create all the facts.
- **DataFlowGraph.java**: Class that creates the graph for the returnsSelf fact.
- **DataflowPathFinder.java**: Class that is responsible for finding a path in a function definition from a paramater value to a return value (i.e. checking if a parameter is also returned).

**tests**: Contains the unittests for the different facts, also contains some fake classes to be used int the tests.

- **facts**: Unittests for the different facts that are supported.
- **ArrayListFile.java**: Test file class that is used instead of a real file.
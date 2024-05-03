# Overview of packages and classes in the factexporter

The application is devided into three main packages. Sometimes these packages are also subdivided into subpackages. The most important classes and packages are described down below.

Most of the classes have the most highlevel methods at the top of the class. Going down in the class it becomes more detailed (the **ReturnsSelf.java** class is a good example). This should make the classes more readable. You will also see the public methods at the top of the class, the private classes will be lower in the class. Every class that could be made private is made private, making a package self contained as much as possible. Of course this is not always possible because some classes need other classes.

## factexporter
Package with the main classes for the creation of the facts. Contains the **FactExporter.java** class which is the most important entry point into the rest of the application. This is the class which constructs all the different facts.
- **adapters**: Adapters and builders necessary to convert Ghidra datastructures to our own datastructures.
- **datastructures**: The internal datastructures that our application uses (**File.java** is the interface each exporting class has to conform to).
- **export**: Exporting of the facts (for now only supports .txt files).
- **facts**: The different facts that we are working on at the moment (**Fact.java** is the interface each fact has to conform to).
    - **ReturnsSelf.java**: most tested and thought out fact

## myghidra
Ghidra classes that are necessary to get the data or knowledge out of ghidra into our own application

- **FactExporterPlugin.java**: Plugin that was each initially to create a simple plugin (is used for simple testing sometimes)
- **FactExporterAnalyzer.java**: Main entry point for Ghidra. This analyzer is loaded into Ghidra and connects to the FactExporter.java to create all the facts.
- **DataFlowGraph.java**: Class that creates the graph for the returnsSelf fact.
- **DataflowPathFinder.java**: Class that is responsible for finding a path in a function definition from a paramater value to a return value (i.e. checking if a parameter is also returned).

## tests 
Contains the unittests for the different facts, also contains some fake classes to be used in the tests.

- **facts**: Unittests for the different facts that are supported.
- **ArrayListFile.java**: Test file class that is used instead of a real file.
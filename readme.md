# Factexporter analyzer in Ghidra for OOAnalyzer

This factexporter is used to explore if the decompilation capabilities of Ghidra can improve the decompilation results of object
oriented constructs in [OOAnalyzer](https://github.com/cmu-sei/pharos/blob/master/tools/ooanalyzer/ooanalyzer.pod).

The factexporter was created during a research that looked to improve the decompilation of C++ code. 
The research was done at the *Open Universiteit* in the Netherlands.

The main contributor is [Jeroen van der Zwam](https://github.com/jeroenvanderzwam).

This analyzer is run inside the [Ghidra](https://ghidra-sre.org/) framework.
To install Ghidra and the factexporter analyzer follow the [Ghidra installation guide](https://ghidra-sre.org/InstallationGuide.html).

For convenience it is also possible to import the analyzer with the provided 

To run the factexporter you can either import the analyer in Ghidra with [zip file](ghidra_11.0_PUBLIC_20240112_FactExporter.zip).
Or you can build the analyzer yourself with Eclipse. For that you need the [GhidraDev](https://ghidra-sre.org/InstallationGuide.html#Development). 

To run the analyzer you can open Ghidra, import the analyzer and run the analyzer on a binary.
Only Windows x64 and x86 are tested, for now.

When in Ghidra go to Analysis -> Analyze All Open and make sure you see the fact exporter analyser.

![Alt text](relative images/AnalysisOptions.png?raw=true "Ghidra Analysis options")
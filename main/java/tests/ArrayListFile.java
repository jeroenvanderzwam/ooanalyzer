package tests;

import java.util.ArrayList;
import java.util.List;

import factexporter.export.File;

public class ArrayListFile implements File 
{

	private ArrayList<String> facts;
	
	@Override
	public void open() {
		facts = new ArrayList<String>();
	}

	@Override
	public void write(String text) {
		facts.add(text);
	}

	@Override
	public void close()
	{
		facts = new ArrayList<String>();
	}

	@Override
	public List<String> read() 
	{
		return facts;
	}

}

package export;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;

public class TextFile implements File
{
	private PrintWriter printWriter;
	private String fileName;
	private String format;
	
	public TextFile(String fName)
	{
		fileName = fName;
		format = "UTF-8";
	}
	
	TextFile(String fName, String form)
	{
		fileName = fName;
		format = form;
	}
	
	@Override
	public void open() {
		printWriter = null;
		try {
			printWriter = new PrintWriter(fileName, format);
		} catch (FileNotFoundException e1) {
			e1.printStackTrace();
		} catch (UnsupportedEncodingException e1) {
			e1.printStackTrace();
		}
		
	}

	@Override
	public void write(String text) {
		printWriter.println(text);
	}

	@Override
	public void close() {
		printWriter.close();
		
	}

	@Override
	public List<String> read() {
		var output = new ArrayList<String>();
		
		BufferedReader bufferedReader = null;
		try {
			bufferedReader = new BufferedReader(new FileReader(fileName));
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		String currentLine;
        try {
			while ((currentLine = bufferedReader.readLine()) != null) {
			    output.add(currentLine);
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return output;
	}

}

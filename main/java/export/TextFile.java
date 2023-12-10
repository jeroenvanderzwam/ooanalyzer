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
	private PrintWriter _printWriter;
	private String _fileName;
	private String _format;
	
	public TextFile(String fileName)
	{
		_fileName = fileName;
		_format = "UTF-8";
	}
	
	TextFile(String fileName, String format)
	{
		_fileName = fileName;
		_format = format;
	}
	
	@Override
	public void open() {
		_printWriter = null;
		try {
			_printWriter = new PrintWriter(_fileName, _format);
		} catch (FileNotFoundException e1) {
			e1.printStackTrace();
		} catch (UnsupportedEncodingException e1) {
			e1.printStackTrace();
		}
		
	}

	@Override
	public void write(String text) {
		_printWriter.println(text);
	}

	@Override
	public void close() {
		_printWriter.close();
		
	}

	@Override
	public List<String> read() {
		var output = new ArrayList<String>();
		
		BufferedReader bufferedReader = null;
		try {
			bufferedReader = new BufferedReader(new FileReader(_fileName));
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

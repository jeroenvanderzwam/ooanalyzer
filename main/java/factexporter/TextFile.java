package factexporter;

import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;

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

}

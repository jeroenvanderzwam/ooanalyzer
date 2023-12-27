package factexporter.export;

import java.util.List;

public interface File 
{
	void open();
	void write(String text);
	List<String> read();
	void close();
}

package factexporter;

public interface File 
{
	void open();
	void write(String text);
	void close();
}

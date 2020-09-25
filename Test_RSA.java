import java.io.FileDescriptor;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import javax.crypto.*;
import java.security.InvalidKeyException;


public class Test_RSA{

	
    // Tu programa comienza con una llamada a main().
    // Imprime "Hola Mundo" a la ventana de la terminal.
    public static void main(String args[])    
    {
    	try{
			RSALibrary r;

			r = new RSALibrary();
			r.generateKeys();
	}catch(IOException e){
		System.out.println("Exception: " + e.getMessage());
		System.exit(-1);
	}
	
	}
}
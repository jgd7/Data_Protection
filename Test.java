import java.io.FileDescriptor;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import javax.crypto.*;
import java.security.InvalidKeyException;


public class Test{

	
    // Tu programa comienza con una llamada a main().
    // Imprime "Hola Mundo" a la ventana de la terminal.
    public static void main(String args[])    
    {
    	try{

		SymmetricEncryption s;

    	
		byte[] byteKey;
		byte[] message;

		String llave = "31323334353637383930313233343536";
		byteKey = llave.getBytes();

		String input = "JAVIER";
		message = input.getBytes();

		// Initialization Vector (fixed)

		s = new SymmetricEncryption(byteKey);
		byte[] encrypter_message = s.encryptBlock(message);
		
		} catch (InvalidKeyException e) {
			System.out.println("Exception: " + e.getMessage());
			System.exit(-1);
		}catch (IllegalBlockSizeException e) {
			System.out.println("Exception: " + e.getMessage());
			System.exit(-1);
		}catch (BadPaddingException e) {
			System.out.println("Exception: " + e.getMessage());
			System.exit(-1);
		}
	}
}
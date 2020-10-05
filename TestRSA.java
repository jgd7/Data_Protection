import java.io.File;
import java.io.FileDescriptor;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import javax.crypto.*;
import java.security.InvalidKeyException;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.*;
import java.security.spec.*;


public class Test_RSA{

	
	
	
    // Tu programa comienza con una llamada a main().
    // Imprime "Hola Mundo" a la ventana de la terminal.
    public static void main(String args[])    
    {
    	// String to hold name of the public key file.
  		final String PUBLIC_KEY_FILE = "./public.key";
  		//String to hold the name of the private key file.
  		final String PRIVATE_KEY_FILE = "./private.key";

  		RSALibrary r;
  		FileInputStream keyfin;
  		PublicKey publicKey;
  		PrivateKey privateKey;
  		File file;
  		byte key_bytes[];

    	try{
    		// Generate RSA keys
			r = new RSALibrary();
			// r.generateKeys();

			// Encrypt
    		// Open public key
    		file = new File(PUBLIC_KEY_FILE);
			key_bytes = new byte[(int)file.length()];
			keyfin = new FileInputStream(file);
			keyfin.read(key_bytes);
			keyfin.close();

			EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(key_bytes);
			publicKey = KeyFactory.getInstance("RSA").generatePublic(publicKeySpec);

			// Encrypt message
			String input = "Ana es una freak";
			byte[] message = input.getBytes();

			byte[] ciphertext = r.encrypt(message, publicKey);

			System.out.println(ciphertext);

			// Decrypt
			// Generate private key
			file = new File(PRIVATE_KEY_FILE);
			key_bytes = new byte[(int)file.length()];
			keyfin = new FileInputStream(file);
			keyfin.read(key_bytes);
			keyfin.close();

			EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(key_bytes);
			privateKey = KeyFactory.getInstance("RSA").generatePrivate(privateKeySpec);
			String plaintext = new String(r.decrypt(ciphertext, privateKey));
			System.out.println(plaintext);



	}catch(IOException e){
		System.out.println("Exception: " + e.getMessage());
		System.exit(-1);
	}catch(NoSuchAlgorithmException e){
		System.out.println("Exception: " + e.getMessage());
		System.exit(-1);
	}catch(InvalidKeySpecException e){
		System.out.println("Exception: " + e.getMessage());
		System.exit(-1);
	}
	
	}
}
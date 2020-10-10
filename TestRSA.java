import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import javax.crypto.*;
import java.security.*;
import java.security.spec.*;


public class TestRSA{

    public static void main(String args[]){
    	
    	/* Testing the implemented functions for encrypting
    	   and decrypting with RSA

    		Args:
        		arg[0] (str): txt to be encrypted.

    		Output:
        		Generates files .enc and .dec for the encrypted
        		and decrypted version respectively
    	*/

    	// String to hold name of the public key file.
  		final String PUBLIC_KEY_FILE = "./public.key";
  		//String to hold the name of the private key file.
  		final String PRIVATE_KEY_FILE = "./private.key";

  		RSALibrary r;
  		FileInputStream keyfin;
  		FileOutputStream out;
  		PublicKey publicKey;
  		PrivateKey privateKey;
  		File file;
  		byte key_bytes[];

  		byte[] plaintext = null;

  		// Extract text
		plaintext = args[0].getBytes();

    	try{
    		// Init RSA class
			r = new RSALibrary();

			// Geneated public and private keys
			r.generateKeys();

			/*************************************************************************************/
			/* Read private and public key
		    /*************************************************************************************/

		    // Read public key
    		file = new File(PUBLIC_KEY_FILE);
			key_bytes = new byte[(int)file.length()];
			keyfin = new FileInputStream(file);
			keyfin.read(key_bytes);
			keyfin.close();

			EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(key_bytes);
			publicKey = KeyFactory.getInstance("RSA").generatePublic(publicKeySpec);

			// Read private key
			file = new File(PRIVATE_KEY_FILE);
			key_bytes = new byte[(int)file.length()];
			keyfin = new FileInputStream(file);
			keyfin.read(key_bytes);
			keyfin.close();

			EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(key_bytes);
			privateKey = KeyFactory.getInstance("RSA").generatePrivate(privateKeySpec);
			
			/*************************************************************************************/
			/* Encryption
		    /*************************************************************************************/

			// Encrypt plaintext
			byte[] ciphertext = r.encrypt(plaintext, publicKey);

			// Print ciphertext
			System.out.println("Text encrypted: " + new String(ciphertext));

			/*************************************************************************************/
			/* Sign
		    /*************************************************************************************/
		    byte[] signed = r.sign(plaintext, privateKey);

		    // Print sign
			System.out.println("Sign: " + new String(signed)); 

			/*************************************************************************************/
			/* Verify sign
		    /*************************************************************************************/
		    boolean verification = r.verify(plaintext, signed, publicKey);

		    // Print sign
			System.out.println("Verification: " + verification); 
			
			/*************************************************************************************/
			/* Decryption
		    /*************************************************************************************/

			byte[] ciphertextDecrypted = r.decrypt(ciphertext, privateKey);

			// Print ciphertext decrypted
			System.out.println("Text decrypted: " + new String(ciphertextDecrypted));


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
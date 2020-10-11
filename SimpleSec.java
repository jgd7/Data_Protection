import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import javax.crypto.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.spec.SecretKeySpec;
import java.util.Scanner;

import java.nio.file.Files;
import java.nio.file.Paths;


public class SimpleSec{

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
  		SymmetricCipher s;
  		SymmetricCipher d;

  		FileInputStream keyfin;
  		FileOutputStream keyfos;
  		PublicKey publicKey;
  		PrivateKey privateKey;
  		File file;
  		byte byteKey[];

  		byte[] privateKeyBytes;
  		PrivateKey privateKeyDecrypted;

  		Scanner myObj = new Scanner(System.in);
  		byte[] sessionKey = null;

    	try{
    		// Init RSA class
			r = new RSALibrary();

			// Geneated public and private keys
			r.generateKeys();

			/*************************************************************************************/
			/* Read and encrypt private key using AES/CBC/Padding with session key (passphrase)
		    /*************************************************************************************/

			// Read private key
			file = new File(PRIVATE_KEY_FILE);
			byteKey = new byte[(int)file.length()];
			keyfin = new FileInputStream(file);
			keyfin.read(byteKey);
			keyfin.close();

			EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(byteKey);
			privateKey = KeyFactory.getInstance("RSA").generatePrivate(privateKeySpec);

		    // Enter passphrase and press Enter
    		System.out.println("Create passphrase of 16 bytes:"); 
    		sessionKey = (myObj.nextLine()).getBytes();  

			s = new SymmetricCipher();
    		
    		byte[] privateKeyEncrypted = s.encryptCBC(privateKey.getEncoded(),sessionKey);

    		// Generate private.key file
			keyfos = new FileOutputStream(PRIVATE_KEY_FILE);
			keyfos.write(privateKeyEncrypted);
			keyfos.close();

			/*************************************************************************************/
			/* Encrypt source file with the session key(passphrase)
		    /*************************************************************************************/
		    // Enter passphrase and press Enter
    		System.out.println("Enter your passphrase:"); 
    		sessionKey = (myObj.nextLine()).getBytes();


		    byte[] plaintext = null;
		
			// Read txt
			try {
				plaintext = Files.readAllBytes(Paths.get("test0.txt"));

			}catch (IOException e) {
		 		System.out.println("Exception: " + e.getMessage());
				System.exit(-1);
			}

			byte[] ciphertext = s.encryptCBC(plaintext, sessionKey);

    		/*************************************************************************************/
			/* Encrypt session key using the public key
		    /*************************************************************************************/

		    // Read public key
    		file = new File(PUBLIC_KEY_FILE);
			byteKey = new byte[(int)file.length()];
			keyfin = new FileInputStream(file);
			keyfin.read(byteKey);
			keyfin.close();

			EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(byteKey);
			publicKey = KeyFactory.getInstance("RSA").generatePublic(publicKeySpec);

			//Encrypt
			byte[] sessionKeyEncrypted = r.encrypt(sessionKey, publicKey);

			/*************************************************************************************/
			/* Sign plaintext
		    /*************************************************************************************/

		    // Read private key
			file = new File(PRIVATE_KEY_FILE);
			byteKey = new byte[(int)file.length()];
			keyfin = new FileInputStream(file);
			keyfin.read(byteKey);
			keyfin.close();

			privateKeyBytes = s.decryptCBC(byteKey, sessionKey);
			privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
			privateKeyDecrypted = KeyFactory.getInstance("RSA").generatePrivate(privateKeySpec);
			
			// Sign
			byte[] plaintextSigned = r.sign(plaintext, privateKeyDecrypted);

			/*************************************************************************************/
			/* Decrypt sessionkey, ciphertext and verify signature
		    /*************************************************************************************/
		    // Read private key
			file = new File(PRIVATE_KEY_FILE);
			byteKey = new byte[(int)file.length()];
			keyfin = new FileInputStream(file);
			keyfin.read(byteKey);
			keyfin.close();

			privateKeyBytes = s.decryptCBC(byteKey, sessionKey);
			privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
			privateKeyDecrypted = KeyFactory.getInstance("RSA").generatePrivate(privateKeySpec);
			
			// Decrypt the sessionKey using the privatekey
		    byte[] sessionKeyDecrypted = r.decrypt(sessionKeyEncrypted, privateKeyDecrypted);

		    // Decrypt the ciphertext using the sessionkey
		    d = new SymmetricCipher();
		    byte[] ciphertextDecrypted = d.decryptCBC(ciphertext,sessionKeyDecrypted);


		    // Read public key
    		file = new File(PUBLIC_KEY_FILE);
			byteKey = new byte[(int)file.length()];
			keyfin = new FileInputStream(file);
			keyfin.read(byteKey);
			keyfin.close();

			publicKeySpec = new X509EncodedKeySpec(byteKey);
			publicKey = KeyFactory.getInstance("RSA").generatePublic(publicKeySpec);

		    // Verify the signature over the decrypted text
		    boolean verification = r.verify(ciphertextDecrypted, plaintextSigned, publicKey);
		    System.out.println(verification);

			

		}catch(Exception e){
			System.out.println("Exception: " + e.getMessage());
			System.exit(-1);
		}
	}
}
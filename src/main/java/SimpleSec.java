import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;
import java.util.concurrent.PriorityBlockingQueue;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;


public class SimpleSec{

	// String to hold name of the public key file.
  	static final String PUBLIC_KEY_FILE = "./public.key";
  	// String to hold the name of the private key file.
  	static final String PRIVATE_KEY_FILE = "./private.key";
	// Charset used to encode/decode
  	static final String CHARSET_NAME = "ISO-8859-1";

	static FileInputStream keyfin;
  	static FileOutputStream keyfout;
  	static FileWriter fileout;
  	static FileReader filein;
  	static File file;

    public static void main(String args[]){
    	
    	if (args[0].equals("-g")){
    		generateAllKeys();
    	}
    	else if (args[0].equals("-e")){
    		encryption(args[1], args[2]);
    	}
    	else if (args[0].equals("-d")){
    		decryption(args[1], args[2]);
    	}
    	else{
    		System.out.println("No command recokgnized.");
    	}
    }

    public static void generateAllKeys(){
    	/*
    	/////////////////////
    	*/
        
        RSALibrary r;
        PrivateKey privateKey;
        SymmetricCipher s;

    	try{
    		// Init RSA class
			r = new RSALibrary();

			// Geneated public and private keys
			r.generateKeys();

			/*************************************************************************************/
			/* Read and encrypt private key using AES/CBC/Padding with session key (passphrase)
		    /*************************************************************************************/

			// Read private key
			byte[] byteKey = read_key(PRIVATE_KEY_FILE);
			EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(byteKey);
			privateKey = KeyFactory.getInstance("RSA").generatePrivate(privateKeySpec);

			// Enter passphrase and press Enter
			byte[] passphrase = generatePassphrase();

			// Encrypt privatekey
			s = new SymmetricCipher();
    		byte[] privateKeyEncrypted = s.encryptCBC(privateKey.getEncoded(), passphrase);

    		// Generate private.key
			keyfout = new FileOutputStream(PRIVATE_KEY_FILE);
			keyfout.write(privateKeyEncrypted);
			keyfout.close();

		}catch(Exception e){
			System.out.println("Exception: " + e.getMessage());
			System.exit(-1);
		}
	}
		
	public static void encryption(String sourceFile, String destinationFile){

		RSALibrary r;
		PublicKey publicKey;
  		PrivateKey privateKey;
  		SymmetricCipher s;

  		byte[] plaintext = null;
  		final String ALGORITHM = "AES";

  		try{
			
			/*************************************************************************************/
			/* Encrypt source file with the session key
		    /*************************************************************************************/
			
			// Generate random AES session key
			SecureRandom rand = new SecureRandom();
			KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
			keyGen.init(128, rand);
			SecretKey sessionKey = keyGen.generateKey();

			// Read source file
			try {
				plaintext = Files.readAllBytes(Paths.get(sourceFile));

			}catch (IOException e) {
		 		System.out.println("Exception: " + e.getMessage());
				System.exit(-1);
			}

			// Encrypt plaintext
			s = new SymmetricCipher();
			byte[] ciphertext = s.encryptCBC(plaintext, sessionKey.getEncoded());

			/*************************************************************************************/
			/* Encrypt session key using the public key
		    /*************************************************************************************/

		    // Read public key
			publicKey = read_public_key(PUBLIC_KEY_FILE);

			//Encrypt session key
			r = new RSALibrary();
			byte[] sessionKeyEncrypted = r.encrypt(sessionKey.getEncoded(), publicKey);

			/*************************************************************************************/
			/* Sign plaintext
		    /*************************************************************************************/

			// Enter passphrase and press Enter
			byte[] passphrase = generatePassphrase();

		    // Decrypt private key
			privateKey = decrypt_private_key(PRIVATE_KEY_FILE, passphrase);
			
			// Sign plaintext
			byte[] plaintextSigned = r.sign(plaintext, privateKey);

			// Generate destination file
			JSONObject object = new JSONObject();
			object.put("Ciphertext", new String(ciphertext, CHARSET_NAME));
			object.put("Sign", new String(plaintextSigned, CHARSET_NAME));
			object.put("SessionKey", new String(sessionKeyEncrypted, CHARSET_NAME));

			fileout = new FileWriter(destinationFile);
			fileout.write(object.toJSONString());
			fileout.close();

		}catch(Exception e){
				System.out.println("Exception: " + e.getMessage());
				System.exit(-1);
			}
	}

	public static void decryption(String sourceFile, String destinationFile){

		SymmetricCipher d;
		RSALibrary r;
		PrivateKey privateKey;
		PublicKey publicKey;
		Object object = null;
		JSONObject jsonObject = null;
		
		byte[] byteKey;

		try{
			/*************************************************************************************/
			/* Decrypt sessionkey, ciphertext and verify signature
		    /*************************************************************************************/

			// Read sourcefile
			JSONParser parser = new JSONParser();

			try {
				//Read JSON file
				object  = parser.parse(new FileReader(sourceFile));
				jsonObject = (JSONObject) object;

			} catch (Exception e ) {
				System.out.println("Exception: " + e.getMessage());
				System.exit(-1);
			}

			byte[] ciphertext = jsonObject.get("Ciphertext").toString().getBytes(CHARSET_NAME);
			byte[] sessionKeyEncrypted =  jsonObject.get("SessionKey").toString().getBytes(CHARSET_NAME);
			byte[] sign = jsonObject.get("Sign").toString().getBytes(CHARSET_NAME);

		    // Enter passphrase and press Enter
			byte[] passphrase = generatePassphrase();

		    // Decrypt private key
			privateKey = decrypt_private_key(PRIVATE_KEY_FILE, passphrase);

			// Decrypt sessionkey using the privatekey
			r = new RSALibrary();
			byte[] sessionKey = r.decrypt(sessionKeyEncrypted, privateKey);

			d = new SymmetricCipher();
			// Decrypt the ciphertext using the sessionkey
		    byte[] ciphertextDecrypted = d.decryptCBC(ciphertext, sessionKey);

		    // Read public key
    		publicKey = read_public_key(PUBLIC_KEY_FILE);

		    // Verify the signature over the decrypted text
		    boolean verification = r.verify(ciphertextDecrypted, sign, publicKey);

		    if(verification == true){
				fileout = new FileWriter(destinationFile);
				fileout.write(new String(ciphertextDecrypted));
				fileout.close();

			}else{
				System.out.println("Signature cannot be verified");
				System.exit(-1);
			}


		}catch(Exception e){
			System.out.println("Exception: " + e.getMessage());
			System.exit(-1);
		}
	}

	public static byte[] generatePassphrase(){

		Scanner myObj = new Scanner(System.in);
		System.out.println("Enter your passphrase:");

		return (myObj.nextLine()).getBytes();
	}

	public static PublicKey read_public_key(String public_key_file) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

		byte[] byteKey = read_key(public_key_file);
		EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(byteKey);
		PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(publicKeySpec);

		return publicKey;
	}

	public static PrivateKey decrypt_private_key(String private_key_file, byte[] passphrase) throws Exception {

		byte[] byteKey = read_key(private_key_file);
		SymmetricCipher d = new SymmetricCipher();
		byte[] privateKeyBytes = d.decryptCBC(byteKey, passphrase);
		EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
		PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(privateKeySpec);

		return privateKey;
	}

	public static byte[] read_key(String key_file) throws IOException {

		file = new File(key_file);
		byte[] byteKey  = new byte[(int)file.length()];
		keyfin = new FileInputStream(file);
		keyfin.read(byteKey);
		keyfin.close();

		return byteKey;
	}
}

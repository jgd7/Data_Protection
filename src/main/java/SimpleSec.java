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
  	static File file;

    public static void main(String args[]){
    	/* Execution of the different functionalities of the SimpleSec

    		Args:
        		args[0] (str): option to be used.
        		args[1] (str): source file if applicable
        		args[2] (str): destination file if applicable
    		Output:
        		Call to the different functions depending on the command
    	*/

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
    	/* Generate public and private key and encrypt private key
           using AES/CBC

    		Args: null
    		Output:
        		Create public.key and private.key
    	*/
        
        RSALibrary r;
        PrivateKey privateKey;
        SymmetricCipher s;

    	try{
    		// Init RSA class
			r = new RSALibrary();

			// Generate public and private keys
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

			// Encrypt private key
			s = new SymmetricCipher();
    		byte[] privateKeyEncrypted = s.encryptCBC(privateKey.getEncoded(), passphrase);

    		// Generate private.key
			keyfout = new FileOutputStream(PRIVATE_KEY_FILE);
			keyfout.write(privateKeyEncrypted);
			keyfout.close();

			System.out.println("Public and private keys has been generated");

		}catch(Exception e){
			System.out.println("Exception: " + e.getMessage());
			System.exit(-1);
		}
	}
		
	public static void encryption(String sourceFile, String destinationFile){
    	/* Encrypt sourceFile, create and encrypt session key and generate signature.

    		Args:
    			sourceFile (str): Name of the source file
    			destinationFile (str): Name of the destination file
    		Output:
        		destinationFile: contains ciphertext, session key encrypted and signature
    	*/

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

			// Generate destination file using JSON format
			JSONObject object = new JSONObject();
			object.put("Ciphertext", new String(ciphertext, CHARSET_NAME));
			object.put("Sign", new String(plaintextSigned, CHARSET_NAME));
			object.put("SessionKey", new String(sessionKeyEncrypted, CHARSET_NAME));

			fileout = new FileWriter(destinationFile);
			fileout.write(object.toJSONString());
			fileout.close();
			System.out.println(destinationFile + " has been generated");

		}catch(Exception e){
				System.out.println("Exception: " + e.getMessage());
				System.exit(-1);
			}
	}

	public static void decryption(String sourceFile, String destinationFile){
    	/* Decrypt sourceFile, session key and validate signature.

    		Args:
    			sourceFile (str): Name of the source file
    			destinationFile (str): Name of the destination file
    		Output:
        		destinationFile: contains plaintext
        		Signature verification message output
    	*/

		SymmetricCipher d;
		RSALibrary r;
		PrivateKey privateKey;
		PublicKey publicKey;
		Object object = null;
		JSONObject jsonObject = null;
		
		byte[] byteKey;

		try{
			/*************************************************************************************/
			/* Decrypt session key, ciphertext and verify signature
		    /*************************************************************************************/

			// Read source file
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

			// Decrypt session key using the private key
			r = new RSALibrary();
			byte[] sessionKey = r.decrypt(sessionKeyEncrypted, privateKey);

			// Decrypt the ciphertext using the session key
			d = new SymmetricCipher();
		    byte[] ciphertextDecrypted = d.decryptCBC(ciphertext, sessionKey);

		    // Read public key
    		publicKey = read_public_key(PUBLIC_KEY_FILE);

		    // Verify the signature over the decrypted text
		    boolean verification = r.verify(ciphertextDecrypted, sign, publicKey);

		    if(verification == true){
				System.out.println("Signature is verified");
				// Generate destination file
				fileout = new FileWriter(destinationFile);
				fileout.write(new String(ciphertextDecrypted));
				fileout.close();
				System.out.println(destinationFile + " has been created");

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
		/* Read passphrase from user input.

    		Args: null
    		Output:
        		passphrase (bytes): contains user passphrase input
    	*/
		Scanner userInput = new Scanner(System.in);
		System.out.println("Enter your passphrase (16 bytes):");

		return (userInput.nextLine()).getBytes();
	}

	public static PublicKey read_public_key(String public_key_file) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
    	/* Read public key from a file.

    		Args:
    			public_key_file (str): name of the public.key
    		Output:
        		publickey (PublicKey): RSA public key
    	*/

		byte[] byteKey = read_key(public_key_file);
		EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(byteKey);
		PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(publicKeySpec);

		return publicKey;
	}

	public static PrivateKey decrypt_private_key(String private_key_file, byte[] passphrase) throws Exception {
    	/* Read and decrypt a private key using user inputs (passphrase).

    		Args:
    			private_key_file (str): name of the private.key
    			passphrase (str): user input
    		Output:
        		privateKey (PrivateKey): RSA private key
    	*/

		byte[] byteKey = read_key(private_key_file);

		// Decrypt private key using passphrase
		SymmetricCipher d = new SymmetricCipher();
		byte[] privateKeyBytes = d.decryptCBC(byteKey, passphrase);
		EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
		PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(privateKeySpec);

		return privateKey;
	}

	public static byte[] read_key(String key_file) throws IOException {
    	/* Read file.

    		Args:
    			key_file (str): name of the file
    		Output:
        		bytekey (bytes): file read bytes
    	*/

		file = new File(key_file);
		byte[] byteKey  = new byte[(int)file.length()];
		keyfin = new FileInputStream(file);
		keyfin.read(byteKey);
		keyfin.close();

		return byteKey;
	}
}

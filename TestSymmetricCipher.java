import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.io.FileOutputStream;


public class TestSymmetricCipher{

    public static void main(String[] args){

    	/* Testing the implemented functions for encrypting
    	   and decrypting with AES using CBC and PKCS5 padding

    		Args:
        		arg[0] (str): txt to be encrypted.
        		arg[1] (str): symmetric key to be used.

    		Output:
        		Generates files .enc and .dec for the encrypted
        		and decrypted version respectively
    	*/

    	byte[] plaintext = null;
		
		// Read txt and key
		try {
			plaintext = Files.readAllBytes(Paths.get(args[0]));

		}catch (IOException e) {
	 		System.out.println("Exception: " + e.getMessage());
			System.exit(-1);
		}

		byte[] byteKey = args[1].getBytes();

		FileOutputStream out;
		SymmetricCipher s;
		SymmetricCipher d;
	
    	try{
    		// Remove extension from the filename
    		String fileName = args[0];
    		fileName = fileName.substring(0, fileName.lastIndexOf("."));

    		/*************************************************************************************/
			/* Encryption using AES/CBC/PKCS5 */
		    /*************************************************************************************/

    		// Encrypt txt using the implemented AES/CBC/PKCS5
			s = new SymmetricCipher();
			byte[] ciphertext = s.encryptCBC(plaintext,byteKey);
			
			// Generate .enc file
			out = new FileOutputStream(fileName + ".enc");
			out.write(ciphertext);
			out.close();

			/*************************************************************************************/
			/* Decryption using AES/CBC/PKCS5 */
		    /*************************************************************************************/

			// Decrypt ciphertext using the implemented AES/CBC/PKCS5
			d = new SymmetricCipher();
			byte[] ciphertextDecrypted = d.decryptCBC(ciphertext,byteKey);

			//Generate .dec file
			out = new FileOutputStream(fileName + ".dec");
			out.write(ciphertextDecrypted);
			out.close();
		
		} catch (Exception e) {
			System.out.println("Exception: " + e.getMessage());
			System.exit(-1);
		}
	}
}
import java.io.FileDescriptor;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import javax.crypto.*;
import java.security.InvalidKeyException;
import java.lang.*;
import java.util.Arrays;

public class SymmetricCipher {

	byte[] byteKey;
	SymmetricEncryption s;
	SymmetricEncryption d;
	
	// Initialization Vector (fixed)
	
	byte[] iv = new byte[] { (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54, 
		(byte)55, (byte)56, (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52,
		(byte)53, (byte)54};

    /*************************************************************************************/
	/* Constructor method */
    /*************************************************************************************/
	public void SymmetricCipher() {
	}

    /*************************************************************************************/
	/* Method to encrypt using AES/CBC/PKCS5 */
    /*************************************************************************************/
	public byte[] encryptCBC (byte[] input, byte[] byteKey) throws Exception {
		
		byte[] ciphertext = null;

		int n_blocks = (int) Math.ceil(input.length/ 16.0);
		int input_with_padding_size =  n_blocks * 16 ;
		int padding_size = input_with_padding_size - input.length;

		// Generate the plaintext with padding
		byte[] input_with_padding = new byte[input_with_padding_size];
		System.arraycopy(input, 0, input_with_padding, 0, input.length);

		// Generate the ciphertext
		for (int i = 1; i < n_blocks; i++) {
			byte[] block = Arrays.copyOfRange(input_with_padding, i, i*16);
			byte[] m_encrypted = s.encryptBlock(block);
		}
		
		return ciphertext;
	}
	
	/*************************************************************************************/
	/* Method to decrypt using AES/CBC/PKCS5 */
    /*************************************************************************************/
	
	
	public byte[] decryptCBC (byte[] input, byte[] byteKey) throws Exception {
	
		
		byte [] finalplaintext = null;

		int n_blocks = (int) Math.ceil(input.length/ 16.0);

			
		// Generate the plaintext
		d = new SymmetricEncryption(byteKey);

		for (int i = 1; i < n_blocks; i++) {
			byte[] block = Arrays.copyOfRange(input, i, i*16);
			byte[] m_decrypted = d.decryptBlock(block);
		}

		// Eliminate the padding
		
		finalplaintext = m_decrypted

		return finalplaintext;

			
		
		
	}
	
}


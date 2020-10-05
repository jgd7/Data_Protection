import java.io.FileDescriptor;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.ByteArrayOutputStream;
import java.security.NoSuchAlgorithmException;
import javax.crypto.*;
import java.security.InvalidKeyException;
import java.lang.*;
import java.util.Arrays;

public class SymmetricCipher {

	byte[] byteKey;
	SymmetricEncryption s;
	SymmetricEncryption d;
	ByteArrayOutputStream outputStream;

	int BLOCK_SIZE = 16;
	byte[] block = new byte[BLOCK_SIZE];
	int numberOfBlocks;
	
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
		/* Funtion implementing encription using AES/CBC/PKCS5

			The function add padding if needed and encrypt the message in
			blocks of 128 bits.

    		Args:
        		input (byte[]): input to be encrypted.
        		byteKey (byte[]): symmetric key to be used.

    		Return:
        		ciphertext: encrypted message
    	*/
		
		byte[] ciphertext = null;
		byte[] blockEncrypted = new byte[BLOCK_SIZE];
		byte[] blockIv = new byte[BLOCK_SIZE];

		s = new SymmetricEncryption(byteKey);
		outputStream = new ByteArrayOutputStream();

		numberOfBlocks = (int) Math.ceil(input.length / 16.0);
		int messageSize =  numberOfBlocks * BLOCK_SIZE ;

		// Generate the plaintext with padding
		int paddingSize =  messageSize - input.length;
		String padding = Integer.toHexString(paddingSize);
		byte[] paddingBytes = padding.getBytes();

		byte[] inputWithPadding = new byte[messageSize];
		System.arraycopy(input, 0, inputWithPadding, 0, input.length);
		
		for(int z = 0; z < paddingSize; z++){
			System.arraycopy(paddingBytes, 0, inputWithPadding, input.length + z, paddingBytes.length);
		}

		// Generate the ciphertext
		for (int i = 0; i < numberOfBlocks; i++) {
			block = Arrays.copyOfRange(inputWithPadding, i * BLOCK_SIZE, (i * BLOCK_SIZE) + BLOCK_SIZE);

			// First block depends on the initial vector (iv)
			// The remaining blocks depend on the previous block
			if(i == 0){
				for(int j = 0; j<block.length; j++){
					blockIv[j] = (byte) (block[j] ^ iv[j]);
				}
			}else{
				for(int j = 0; j<block.length; j++){
					blockIv[j] = (byte) (block[j] ^ blockEncrypted[j]);
				}
			}

			blockEncrypted = s.encryptBlock(blockIv);

			// Concatenate block encrypted
			outputStream.write(blockEncrypted);
		}

		ciphertext = outputStream.toByteArray();
		
		return ciphertext;
	}
	
	/*************************************************************************************/
	/* Method to decrypt using AES/CBC/PKCS5 */
    /*************************************************************************************/
	
	
	public byte[] decryptCBC (byte[] input, byte[] byteKey) throws Exception {
		/* Funtion implementing decription using AES/CBC/PKCS5

			The function decrypt the message in blocks of 128 bits and remove
			the padding if it has been applied

    		Args:
        		input (byte[]): input to be decrypted.
        		byteKey (byte[]): symmetric key to be used.

    		Return:
        		finalplaintext: decrypted message
    	*/
	
		byte [] finalplaintext = null;
		byte[] blockDecrypted = new byte[BLOCK_SIZE];
		byte[] blockPrevious = new byte[BLOCK_SIZE];

		d = new SymmetricEncryption(byteKey);
		outputStream = new ByteArrayOutputStream();

		numberOfBlocks = (int) Math.ceil(input.length/ 16.0);

		// Generate the ciphertext
		for (int i = 0; i < numberOfBlocks; i++) {
			block = Arrays.copyOfRange(input, i * BLOCK_SIZE, (i * BLOCK_SIZE) + BLOCK_SIZE);
			blockDecrypted = d.decryptBlock(block);
		
			// First block depends on the initial vector (iv)
			// The remaining blocks depend on the previous block
			if(i == 0){
				for(int j = 0; j<blockDecrypted.length; j++){
					blockDecrypted[j] = (byte) (blockDecrypted[j] ^ iv[j]);
				}
			}
			else{
				for(int j = 0; j<blockDecrypted.length; j++){
					blockDecrypted[j] = (byte) (blockDecrypted[j] ^ blockPrevious[j]);
				}
			}

			System.arraycopy(block, 0, blockPrevious, 0, block.length);
			outputStream.write(blockDecrypted);
		}

		// Eliminate the padding
		byte[] padding = Arrays.copyOfRange(blockDecrypted, blockDecrypted.length -1, blockDecrypted.length);
		int paddingSize = Integer.parseInt(new String(padding),16);

		finalplaintext = outputStream.toByteArray();

		// Check if padding is needed
		if(paddingSize == 16 - ((input.length - paddingSize) % 16)){
			finalplaintext = Arrays.copyOfRange(finalplaintext, 0, finalplaintext.length - paddingSize);
		}

		return finalplaintext;	
		
	}
	
}


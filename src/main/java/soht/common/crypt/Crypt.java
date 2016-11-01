package soht.common.crypt;

import java.io.InputStream;
import java.io.OutputStream;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import lombok.Setter;

public class Crypt {

	private static final String ALGORITHM = "AES";
	private static final String ALGORITHM_MODE = "CBC";
	private static final String ALGORITHM_PADDING = "PKCS5Padding";
	private static final String TRANSFORMATION = ALGORITHM + "/" + ALGORITHM_MODE + "/" + ALGORITHM_PADDING;

	public static boolean isSharedSecretvalid(String sharedSecret) {
		return !sharedSecret.isEmpty() && sharedSecret.length() >= 16;
	}

	@Setter private String sharedSecret;

	private byte[] getSharedSecret() {
		return sharedSecret.getBytes();
	}

	private Cipher decryptCipher;
	private Cipher encryptCipher;

	public boolean configured() {
		return decryptCipher != null && encryptCipher != null;
	}

	public void updateCiphers() {
		decryptCipher = null;
		encryptCipher = null;

		if (sharedSecret == null || sharedSecret.isEmpty()) return;

		if (!isSharedSecretvalid(sharedSecret))
			throw new CryptException("Configured shared secret is not valid: \"" + sharedSecret + "\"");

		try {
			decryptCipher = Cipher.getInstance(TRANSFORMATION);
			decryptCipher.init(Cipher.DECRYPT_MODE,
					new SecretKeySpec(getSharedSecret(), ALGORITHM),
					new IvParameterSpec(new byte[decryptCipher.getBlockSize()]));
		} catch (Exception e) {
			decryptCipher = null;
			throw new CryptException("Failed to initialize decrypt cipher", e);
		}

		try {
			encryptCipher = Cipher.getInstance(TRANSFORMATION);
			encryptCipher.init(Cipher.ENCRYPT_MODE,
					new SecretKeySpec(getSharedSecret(), ALGORITHM),
					new IvParameterSpec(new byte[encryptCipher.getBlockSize()]));
		} catch (Exception e) {
			encryptCipher = null;
			throw new CryptException("Failed to initialize encrypt cipher", e);
		}
	}

	public byte[] decrypt(byte[] enc) throws IllegalBlockSizeException, BadPaddingException {
		if (decryptCipher == null)
			throw new CryptException("Decrypt cipher not available");
		return decryptCipher.doFinal(enc);
	}

	public CipherInputStream decrypt(InputStream enc) {
		if (decryptCipher == null)
			throw new CryptException("Decrypt cipher not available");
		return new CipherInputStream(enc, decryptCipher);
	}

	public byte[] encrypt(byte[] clear) throws IllegalBlockSizeException, BadPaddingException {
		if (encryptCipher == null)
			throw new CryptException("Encrypt cipher not available");
		return encryptCipher.doFinal(clear);
	}

	public CipherOutputStream encrypt(OutputStream clear) {
		if (encryptCipher == null)
			throw new CryptException("Encrypt cipher not available");
		return new CipherOutputStream(clear, encryptCipher);
	}

}

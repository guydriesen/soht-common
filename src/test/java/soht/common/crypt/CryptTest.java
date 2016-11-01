package soht.common.crypt;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;

import org.apache.commons.codec.binary.Base64InputStream;
import org.apache.commons.codec.binary.Base64OutputStream;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class CryptTest {

	private static final String SHARED_SECRET = "kNLgP2xOhk7Dd0Bk";
	private static final String TEXT_CLEAR = "CM1lVshr5RpvMX48jOc0jdTdb";
	private static final String TEXT_ENC = "ibh8w9zKIbARaU19y604OgIKDPX6D0Cb3rzGrutSDsM=";

	private Crypt crypt;

	@Before
	public void init() {
		crypt = new Crypt();
		crypt.setSharedSecret(SHARED_SECRET);
		crypt.updateCiphers();
	}

	@Test
	public void encryptString() throws IllegalBlockSizeException, BadPaddingException {
		String enc = Base64.getEncoder().encodeToString(crypt.encrypt(TEXT_CLEAR.getBytes()));
		Assert.assertEquals(TEXT_ENC, enc);
	}

	@Test
	public void decryptString() throws IllegalBlockSizeException, BadPaddingException {
		String clear = new String(crypt.decrypt(Base64.getDecoder().decode(TEXT_ENC)));
		Assert.assertEquals(TEXT_CLEAR, clear);
	}

	@Test
	public void encryptStream() {
		boolean doEncode = true;
		int lineLength = -1;
		byte[] lineSeparator = new byte[] {};

		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		Base64OutputStream b64os = new Base64OutputStream(baos, doEncode, lineLength, lineSeparator);
		CipherOutputStream cos = crypt.encrypt(b64os);
		OutputStreamWriter osw = new OutputStreamWriter(cos);
		PrintWriter pw = new PrintWriter(osw, true);
		pw.print(TEXT_CLEAR);
		pw.close();

		Assert.assertEquals(TEXT_ENC, baos.toString());
	}

	@Test
	public void decryptStream() {
		boolean doEncode = false;

		ByteArrayInputStream bais = new ByteArrayInputStream(TEXT_ENC.getBytes());
		Base64InputStream b64is = new Base64InputStream(bais, doEncode);
		CipherInputStream cis = crypt.decrypt(b64is);

		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		try {
			byte[] buffer = new byte[1024];
			int length;
			while ((length = cis.read(buffer)) != -1) {
				baos.write(buffer, 0, length);
			}
		} catch (IOException e) {
			Assert.fail(e.getMessage());
		}

		Assert.assertEquals(TEXT_CLEAR, baos.toString());
	}

	@Test
	public void status() {
		Assert.assertEquals(true, crypt.configured());

		crypt.setSharedSecret("");
		crypt.updateCiphers();
		Assert.assertEquals(false, crypt.configured());
	}

}

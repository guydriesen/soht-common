package soht.common.crypt;

public class CryptException extends RuntimeException {

	private static final long serialVersionUID = 1L;

	public CryptException() {
		super();
	}

	public CryptException(Throwable t) {
		super(t);
	}

	public CryptException(String string) {
		super(string);
	}

	public CryptException(String string, Throwable t) {
		super(string, t);
	}

}

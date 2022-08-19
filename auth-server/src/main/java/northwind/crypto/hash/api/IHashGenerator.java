package northwind.crypto.hash.api;

import javax.crypto.SecretKey;

public interface IHashGenerator {
	public SecretKey generateSecretKey() ;
}

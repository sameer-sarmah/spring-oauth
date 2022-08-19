package northwind.crypto.hash.impl;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.springframework.stereotype.Component;

import northwind.crypto.hash.api.IHashGenerator;

@Component
public class SHA256HashGenerator implements IHashGenerator{
	
	@Override
	public SecretKey generateSecretKey() {
		SecretKey hmacKey;
		try {
			hmacKey = KeyGenerator.getInstance("HmacSha256").generateKey();
		} catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
		return hmacKey;
	}
}

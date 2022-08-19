package northwind.crypto.asymmetric.impl;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.springframework.stereotype.Component;

import northwind.crypto.api.KeyPairType;
import northwind.crypto.asymmetric.api.IKeyGenerator;
import northwind.util.TrustStoreUtil;

@Component
public class RsaKeyGenerator implements IKeyGenerator{

	@Override
	public KeyPair generateKey() {
		KeyPair keyPair;
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			keyPair = keyPairGenerator.generateKeyPair();
			PrivateKey privateKey = keyPair.getPrivate();
			PublicKey publicKey = keyPair.getPublic();
			TrustStoreUtil.analysePrivateKey(privateKey);
			TrustStoreUtil.analysePublicKey(publicKey);
		} catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
		return keyPair;
	}

	@Override
	public KeyPairType getType() {
		return KeyPairType.RSA;
	}
}

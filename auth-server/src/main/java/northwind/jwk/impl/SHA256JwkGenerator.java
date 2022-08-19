package northwind.jwk.impl;

import java.util.UUID;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetSequenceKey;

import northwind.crypto.api.KeyPairType;
import northwind.crypto.hash.api.IHashGenerator;
import northwind.jwk.api.IJwkGenerator;

@Component
public class SHA256JwkGenerator implements IJwkGenerator{

	@Autowired
	private IHashGenerator hashGenerator;
	
	@Override
	public JWK generateJwk() {
		SecretKey secretKey = hashGenerator.generateSecretKey();
		return new OctetSequenceKey.Builder(secretKey)
				.keyID(UUID.randomUUID().toString())
				.build();
	}

	@Override
	public KeyPairType getType() {
		return KeyPairType.SHA256;
	}
}

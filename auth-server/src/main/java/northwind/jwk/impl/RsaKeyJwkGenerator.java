package northwind.jwk.impl;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;

import northwind.crypto.api.KeyPairType;
import northwind.crypto.asymmetric.api.IKeyGenerator;
import northwind.jwk.api.IJwkGenerator;

@Component
public class RsaKeyJwkGenerator implements IJwkGenerator {

	@Autowired
	private List<IKeyGenerator> keyGenerators;

	@Override
	public JWK generateJwk() {
		Optional<IKeyGenerator> generatorOptional = keyGenerators.stream()
				.filter(keyGenerator -> keyGenerator.getType().equals(KeyPairType.RSA)).findAny();
		if (generatorOptional.isPresent()) {
			KeyPair keyPair = generatorOptional.get().generateKey();
			RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
			RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
			return new RSAKey.Builder(publicKey)
							.privateKey(privateKey)
							.keyID(UUID.randomUUID().toString())
							.build();
		}
		return null;
	}

	@Override
	public KeyPairType getType() {
		return KeyPairType.RSA;
	}
}

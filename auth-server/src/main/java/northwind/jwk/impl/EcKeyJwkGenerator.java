package northwind.jwk.impl;

import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;

import northwind.crypto.api.KeyPairType;
import northwind.crypto.asymmetric.api.IKeyGenerator;
import northwind.jwk.api.IJwkGenerator;

@Component
public class EcKeyJwkGenerator implements IJwkGenerator {

	@Autowired
	private List<IKeyGenerator> keyGenerators;
	
	@Override
	public JWK generateJwk() {
		Optional<IKeyGenerator> generatorOptional = keyGenerators.stream()
				.filter(keyGenerator -> keyGenerator.getType().equals(KeyPairType.EC))
				.findAny();
		if(generatorOptional.isPresent()) {
			KeyPair keyPair = generatorOptional.get().generateKey();
			ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
			ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
			Curve curve = Curve.forECParameterSpec(publicKey.getParams());
			return new ECKey.Builder(curve, publicKey)
					.privateKey(privateKey)
					.keyID(UUID.randomUUID().toString())
					.build();
		}
		return null;
	}

	@Override
	public KeyPairType getType() {
		return KeyPairType.EC;
	}
}

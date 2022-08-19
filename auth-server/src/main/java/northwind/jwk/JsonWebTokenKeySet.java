package northwind.jwk;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;

import northwind.crypto.api.KeyPairType;
import northwind.jwk.api.IJwkGenerator;

@Component
public class JsonWebTokenKeySet {
		
	@Autowired
	private List<IJwkGenerator> jwkGenerators;
	
	public RSAKey generateRsa() {
		IJwkGenerator jwkGenerator = getJwkGenerator(KeyPairType.RSA);
		if(Objects.nonNull(jwkGenerator)) {
			return (RSAKey) jwkGenerator.generateJwk();
		}
		return null;
	}

	public ECKey generateEc() {
		IJwkGenerator jwkGenerator = getJwkGenerator(KeyPairType.EC);
		if(Objects.nonNull(jwkGenerator)) {
			return (ECKey) jwkGenerator.generateJwk();
		}
		return null;
	}

	private IJwkGenerator getJwkGenerator(KeyPairType type) {
		Optional<IJwkGenerator> jwkGeneratorOptional = jwkGenerators.stream()
				.filter(jwkGenerator -> jwkGenerator.getType().equals(type))
				.findAny();
		if(jwkGeneratorOptional.isPresent()) {
			return jwkGeneratorOptional.get();
		}
		return null;
	}
}

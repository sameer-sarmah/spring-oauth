package northwind.jwk.api;

import com.nimbusds.jose.jwk.JWK;

import northwind.crypto.api.KeyPairType;

public interface IJwkGenerator {
	JWK generateJwk();
	KeyPairType getType();
}

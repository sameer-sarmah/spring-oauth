package northwind.crypto.asymmetric.api;

import java.security.KeyPair;

import northwind.crypto.api.KeyPairType;

public interface IKeyGenerator {
	KeyPair generateKey();
	KeyPairType getType();
}

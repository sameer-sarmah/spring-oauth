package northwind.util;

import java.nio.charset.Charset;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class TrustStoreUtil {

	private static final Logger LOG = LoggerFactory.getLogger(TrustStoreUtil.class);
	
	private static final String EQUAL = "=";
	private static final String COMMA = ",";

	
	public static void analysePublicKey(PublicKey publicKey) {
		StringBuilder builder = new StringBuilder("PublicKey metadata.");
		analyseKey(publicKey, builder);
	}
	
	private static void analyseKey(Key key,StringBuilder builder) {
		 builder.append("Algorithm").append(EQUAL).append(key.getAlgorithm())
				//.append("Key").append(EQUAL).append(new String(key.getEncoded(),Charset.defaultCharset()))
				.append("Format").append(EQUAL).append(key.getFormat());
		 LOG.info(builder.toString());
	}
	
	public static void analysePrivateKey(PrivateKey privateKey) {
		StringBuilder builder = new StringBuilder("PrivateKey metadata.");
		analyseKey(privateKey, builder);
	}
}

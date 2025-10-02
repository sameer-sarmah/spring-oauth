package northwind.service;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RequestCallback;
import org.springframework.web.client.ResponseExtractor;
import org.springframework.web.client.RestTemplate;

import northwind.model.Product;
import northwind.util.Constants;

@Component
public class OAuthTokenService {
	
	@Value("${oauth-token-url}")
	private String oauthTokenUrl;
	
	@Value("${oauth-client-id}")
	private String clientId;
	
	@Value("${oauth-client-secret}")
	private String clientSecret;
	
	@Value("${resource-url}")
	private String resourceUrl;
	
	@Autowired
	private RestTemplate restTemplate;	
	
	private static final Logger LOGGER = LoggerFactory.getLogger(OAuthTokenService.class);

	private HttpEntity<MultiValueMap<String, String>> createHttpEntity() {
		HttpHeaders headers = new HttpHeaders();
		String authHeader = createBasicAuthHeader(clientId, clientSecret);
		headers.add(HttpHeaders.AUTHORIZATION, authHeader);
		headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
		MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
		form.add(Constants.CLIENT_ID, clientId);
		form.add(Constants.CLIENT_SECRET, clientSecret);
		form.add(Constants.GRANT_TYPE, Constants.CLIENT_CRED);
		form.add(Constants.CLIENT_SCOPES, "message.read message.write");
		return new HttpEntity<>(form, headers);
	}
	
	public Optional<OAuth2Response> generateOAuthToken() {
		LOGGER.info("{} generating oauth2 access token");
		HttpEntity<MultiValueMap<String, String>> httpEntity = createHttpEntity();
		try {
			ResponseEntity<OAuth2Response> response = restTemplate.postForEntity(oauthTokenUrl, httpEntity, OAuth2Response.class);
			LOGGER.info("{} oauth2 access token generated successfully");
			return Optional.of( response.getBody());	
		} catch (Exception e) {
			LOGGER.error(e.getMessage(), e);
		}
		return Optional.empty();
	}
	
	public MultiValueMap<String, String> getAuthHeader() {

		MultiValueMap<String, String> header = new LinkedMultiValueMap<>();
		Optional<OAuth2Response> response= generateOAuthToken();
		if(response.isPresent()) {
			String accessToken = response.get().getAccess_token();
			String headerValue = Constants.HEADER_BEARER + " " + accessToken;
			header.add(Constants.AUTHORIZATION_HEADER_NAME, headerValue);
		}
		return header;	
	}
	
	public void invokeResourceUrl(Product product) {
		try {
			MultiValueMap<String, String> header = getAuthHeader();
			HttpHeaders headers = new HttpHeaders();
			headers.setContentType(MediaType.APPLICATION_JSON);
			headers.addAll(header);
			HttpEntity<Product> httpEntity = new HttpEntity<>(product, headers);
			ResponseEntity<String> response = restTemplate.postForEntity(resourceUrl, httpEntity, String.class);
			LOGGER.info(response.getStatusCode().toString());
		} catch (Exception e) {
			LOGGER.error(e.getMessage(), e);
		}
	}
	
	public void invokeResourceUrl(Product product,RequestCallback callback,ResponseExtractor responseExtractor) {
		try {
			HttpEntity<Product> httpEntity = new HttpEntity<>(product);
			restTemplate.execute(resourceUrl, HttpMethod.POST, callback, responseExtractor);
		} catch (Exception e) {
			LOGGER.error(e.getMessage(), e);
		}
	}
	
	private String encodeBasicAuth(String username, String password) {
        String credentials = username + ":" + password;
        return Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
    }
    
    private String createBasicAuthHeader(String username, String password) {
        String encodedCredentials = encodeBasicAuth(username, password);
        return "Basic " + encodedCredentials;
    }
	
}

package northwind.http;

import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RequestCallback;

import northwind.service.OAuth2Response;
import northwind.service.OAuthTokenService;
import northwind.util.Constants;

@Component
public class HttpRequestCallback implements RequestCallback {
	
	@Autowired
	private OAuthTokenService oAuthTokenService;
	
	private static final Logger LOGGER = LoggerFactory.getLogger(HttpRequestCallback.class);
	
	@Override
	public void doWithRequest(ClientHttpRequest clientHttpRequest) throws java.io.IOException {
		Optional<OAuth2Response> response= oAuthTokenService.generateOAuthToken();
		if(response.isPresent()) {
			LOGGER.info("Access Token: "+response.get().getAccess_token());
			String accessToken = response.get().getAccess_token();
			String headerValue = Constants.HEADER_BEARER + " " + accessToken;
			clientHttpRequest.getHeaders().add(Constants.AUTHORIZATION_HEADER_NAME, headerValue);
			clientHttpRequest.getHeaders().add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
		}
	}
}

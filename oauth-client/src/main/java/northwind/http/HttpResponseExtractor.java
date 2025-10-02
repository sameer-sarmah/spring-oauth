package northwind.http;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.client.ResponseExtractor;

@Component
public class HttpResponseExtractor implements ResponseExtractor{

	private static final Logger LOGGER = LoggerFactory.getLogger(HttpResponseExtractor.class);
	
	@Override
	public Object extractData(ClientHttpResponse response) throws IOException {
		LOGGER.info(response.getStatusCode().toString());
		return null;
	}

}

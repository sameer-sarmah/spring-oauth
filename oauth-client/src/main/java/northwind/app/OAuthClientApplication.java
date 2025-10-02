package northwind.app;

import java.io.InputStream;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Import;
import org.springframework.web.client.RequestCallback;
import org.springframework.web.client.ResponseExtractor;

import com.fasterxml.jackson.databind.ObjectMapper;

import northwind.config.AppConfig;
import northwind.model.Product;
import northwind.service.OAuth2Response;
import northwind.service.OAuthTokenService;





@SpringBootApplication
@ComponentScan(basePackages = "northwind")
@Import({AppConfig.class})
public class OAuthClientApplication  implements ApplicationRunner {
	
	@Autowired
	private OAuthTokenService oAuthTokenService;
	
	@Autowired
	private ResponseExtractor responseExtractor;
	
	@Autowired
	private RequestCallback requestCallback;
	
	private static final Logger LOGGER = LoggerFactory.getLogger(OAuthClientApplication.class);
	
	public static void main(String[] args) {
		SpringApplication.run(OAuthClientApplication.class, args);
		LOGGER.info("##########OAuthClientApplication########");
		
	}

	@Override
	public void run(ApplicationArguments args) throws Exception {
//		Optional<OAuth2Response> response= oAuthTokenService.generateOAuthToken();
//		if(response.isPresent()) {
//			LOGGER.info("Access Token: "+response.get().getAccess_token());
//		}	
		Product product = createProduct();
	//	oAuthTokenService.invokeResourceUrl(product);
		oAuthTokenService.invokeResourceUrl(product,requestCallback,responseExtractor);
	}
	
	
	private Product createProduct() {
		try {
			InputStream in = OAuthClientApplication.class.getClassLoader()
					.getSystemResourceAsStream("product.json");
			ObjectMapper objectMapper = new ObjectMapper();
			Product product = objectMapper.readValue(in, Product.class);
			return product;
		} catch (Exception e) {
			LOGGER.error(e.getMessage(), e);
		}
		return null;
	}

}
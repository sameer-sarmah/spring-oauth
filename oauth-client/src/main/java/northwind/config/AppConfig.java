package northwind.config;

import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.http.client.BufferingClientHttpRequestFactory;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

@Configuration
@ComponentScan(basePackages= {"northwind"})
public class AppConfig {
	
	@Autowired
	private RestTemplateBuilder restTemplateBuilder;
	
	private static final Logger LOGGER = LoggerFactory.getLogger(AppConfig.class);
	
	@Bean
	public static PropertySourcesPlaceholderConfigurer propertySourcesPlaceholderConfigurer() {
		return new PropertySourcesPlaceholderConfigurer();
	}
	
	@Bean
	public RestTemplate createRestTemplate(CloseableHttpClient httpClient) {		
		ClientHttpRequestFactory httpRequestFactory = new BufferingClientHttpRequestFactory(
				new HttpComponentsClientHttpRequestFactory(httpClient));

		RestTemplate restTemplate = restTemplateBuilder.build();
		restTemplate.setRequestFactory(httpRequestFactory);
		return restTemplate;
	}
	
	@Bean
	public CloseableHttpClient createHttpClient() {
		CloseableHttpClient httpClient = HttpClientBuilder.create()
				.build();
		return httpClient;
	}

}

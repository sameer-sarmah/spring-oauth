package northwind.config;

import java.time.Duration;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import northwind.jwk.JsonWebTokenKeySet;

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
//@Import(OAuth2AuthorizationServerConfiguration.class)
@ComponentScan(basePackages= {"northwind"})
public class AuthServerConfig {
	
	@Autowired
	private JsonWebTokenKeySet jwtKeySet;
	
	@Bean 
	@Order(1)
	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
			throws Exception {
		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
//		http
			// Redirect to the login page when not authenticated from the
			// authorization endpoint
//			.exceptionHandling((exceptions) -> exceptions
//				.authenticationEntryPoint(
//					new LoginUrlAuthenticationEntryPoint("/login"))
//			);

		return http.formLogin(Customizer.withDefaults()).build();
	}

//	@Bean 
//	@Order(2)
//	public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
//			throws Exception {
//		http
//			.authorizeHttpRequests((authorize) -> authorize
//				.anyRequest().authenticated()
//			)
//			.httpBasic();
//			// Form login handles the redirect to the login page from the
//			// authorization server filter chain
//			//.formLogin(Customizer.withDefaults());
//
//		return http.build();
//	}

	@Bean 
	public UserDetailsService userDetailsService() {
		UserDetails userDetails = User.withDefaultPasswordEncoder()
				.username("user")
				.password("password")
				.roles("USER")
				.build();

		return new InMemoryUserDetailsManager(userDetails);
	}

	@Bean
	public OAuth2AuthorizationService authorizationService() {
		return new InMemoryOAuth2AuthorizationService();
	}
	
	@Bean 
	public RegisteredClientRepository registeredClientRepository() {
		RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("messaging-client")
				//{noop} refers to NoOpPasswordEncoder 
				.clientSecret("{noop}secret")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.redirectUri("http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc")
				.redirectUri("http://127.0.0.1:8080/authorized")
				.scope(OidcScopes.OPENID)
				.scope("message.read")
				.scope("message.write")
				.clientSettings(ClientSettings.builder()
							.requireAuthorizationConsent(false)
							.requireProofKey(true)
							.build())
				.tokenSettings(TokenSettings.builder()
			      .accessTokenTimeToLive(Duration.ofMinutes(30L))
			      .build())
				.build();

		return new InMemoryRegisteredClientRepository(registeredClient);
	}

	@Bean 
	public JWKSource<SecurityContext> jwkSource() {
		JWKSet jwkSet = new JWKSet(jwtKeySet.generateRsa());
		return new ImmutableJWKSet<>(jwkSet);
	}


	@Bean 
	public ProviderSettings providerSettings() {
		return ProviderSettings.builder().issuer("http://localhost:9000").build();
	}

}

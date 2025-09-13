package northwind.config;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
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
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import northwind.jwk.JsonWebTokenKeySet;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.util.CollectionUtils;

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
@ComponentScan(basePackages= {"northwind"})
public class AuthServerConfig {
	
	@Autowired
	private JsonWebTokenKeySet jwtKeySet;
	@Bean
	@Order(1)
	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {

		OAuth2AuthorizationServerConfigurer  authorizationServerConfigurer =
				OAuth2AuthorizationServerConfigurer.authorizationServer();

	    http
	        //.securityMatcher("/oauth2/**", "/.well-known/**")
			.securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
			.with(authorizationServerConfigurer, (authorizationServer) ->
					authorizationServer
							.oidc(Customizer.withDefaults())	// Enable OpenID Connect 1.0
			)
			.authorizeHttpRequests(authorize -> authorize
					.requestMatchers("/oauth2/token", "/oauth2/authorize", "/oauth2/introspect",
							"/oauth2/revoke", "/.well-known/**")
					.permitAll()
					.anyRequest().authenticated()
			)
	        .csrf(csrf -> csrf.ignoringRequestMatchers(
	            new OrRequestMatcher(
						PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, "/oauth2/token"),
						PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.GET, "/oauth2/authorize"),
						PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, "/oauth2/introspect"),
						PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, "/oauth2/revoke"),
						PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.GET, "/.well-known/**")
	            )
	        ));
	    return http.build();
	}

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
	public AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder().issuer("http://localhost:9000").build();
	}

	@Bean
	public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
	    return context -> {
	        if (context.getTokenType().getValue().equals("access_token")) {
	            // Try to get scopes from different context sources
	            Set<String> scopes = context.getAuthorizedScopes();

	            // If authorized scopes is empty, try to get from the OAuth2TokenContext
	            if (CollectionUtils.isEmpty(scopes)) {
	                // Get scopes from the token request context
	                OAuth2Authorization authorization = context.get(OAuth2Authorization.class);
	                if (authorization != null) {
	                    scopes = authorization.getAuthorizedScopes();
	                }
	            }

	            if (CollectionUtils.isEmpty(scopes)) {
	                RegisteredClient registeredClient = context.get(RegisteredClient.class);
	                if (registeredClient != null) {
	                    // For client_credentials grant, use all client scopes
	                    scopes = registeredClient.getScopes();
	                }
	            }

	            if (!CollectionUtils.isEmpty(scopes)) {
	                List<String> scopesList = new ArrayList<>(scopes);
	                context.getClaims().claim("scope", scopesList);
	                context.getClaims().claim("scp", String.join(" ", scopes));
	            }
	        }
	    };
	}
}

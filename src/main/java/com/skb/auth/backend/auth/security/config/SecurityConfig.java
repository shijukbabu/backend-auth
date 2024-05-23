package com.skb.auth.backend.auth.security.config;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.stream.Collectors;

import javax.sql.DataSource;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.oidc.OidcClientRegistration;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcClientConfigurationAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcClientRegistrationAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.oidc.converter.OidcClientRegistrationRegisteredClientConverter;
import org.springframework.security.oauth2.server.authorization.oidc.converter.RegisteredClientOidcClientRegistrationConverter;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.util.CollectionUtils;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.skb.auth.backend.auth.security.service.AuthService;

@EnableWebSecurity
@Configuration
public class SecurityConfig {

	@Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	AuthenticationManager authenticationManager(AuthService authService) {
		return authenticationManagerBean(authService);
	}

	@Bean
	AuthenticationManager authenticationManagerBean(AuthService authService) {
		return new ProviderManager(Arrays.asList(authenticationProvider(authService)));
	}

	@Bean
	DaoAuthenticationProvider authenticationProvider(AuthService authService) {
		DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
		authProvider.setUserDetailsService(authService);
		authProvider.setPasswordEncoder(passwordEncoder());
		return authProvider;
	}

	@Bean
	@Order(1)
	SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
//		http.getConfigurer(OAuth2AuthorizationServerConfigurer.class).oidc(Customizer.withDefaults()); // Enable OpenID
		// Connect 1.0

		http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
				.oidc(oidc -> oidc.clientRegistrationEndpoint(clientRegistrationEndpoint -> clientRegistrationEndpoint
						.authenticationProviders(configureCustomClientMetadataConverters())));
		http
				// Redirect to the login page when not authenticated from the
				// authorization endpoint
				.exceptionHandling(exceptions -> exceptions.defaultAuthenticationEntryPointFor(
						new LoginUrlAuthenticationEntryPoint("/login"),
						new MediaTypeRequestMatcher(MediaType.TEXT_HTML)))
				// Accept access tokens for User Info and/or Client Registration
				.oauth2ResourceServer(resourceServer -> resourceServer.jwt(Customizer.withDefaults()));
		return http.build();
	}

	@Bean
	@Order(2)
	public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
		http.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
				// Form login handles the redirect to the login page from the
				// authorization server filter chain
				.formLogin(Customizer.withDefaults());

		return http.build();
	}

	public Consumer<List<AuthenticationProvider>> configureCustomClientMetadataConverters() {
		List<String> customClientMetadata = List.of("logo_uri", "contacts");

		return authenticationProviders -> {
			CustomRegisteredClientConverter registeredClientConverter = new CustomRegisteredClientConverter(
					customClientMetadata);
			CustomClientRegistrationConverter clientRegistrationConverter = new CustomClientRegistrationConverter(
					customClientMetadata);

			authenticationProviders.forEach(authenticationProvider -> {
				if (authenticationProvider instanceof OidcClientRegistrationAuthenticationProvider provider) {
					provider.setRegisteredClientConverter(registeredClientConverter);
					provider.setClientRegistrationConverter(clientRegistrationConverter);
				}
				if (authenticationProvider instanceof OidcClientConfigurationAuthenticationProvider provider) {
					provider.setClientRegistrationConverter(clientRegistrationConverter);
				}
			});
		};
	}

	private static class CustomRegisteredClientConverter
			implements Converter<OidcClientRegistration, RegisteredClient> {

		private final List<String> customClientMetadata;
		private final OidcClientRegistrationRegisteredClientConverter delegate;

		private CustomRegisteredClientConverter(List<String> customClientMetadata) {
			this.customClientMetadata = customClientMetadata;
			this.delegate = new OidcClientRegistrationRegisteredClientConverter();
		}

		@Override
		public RegisteredClient convert(OidcClientRegistration clientRegistration) {
			RegisteredClient registeredClient = this.delegate.convert(clientRegistration);
			ClientSettings.Builder clientSettingsBuilder = ClientSettings
					.withSettings(registeredClient.getClientSettings().getSettings());
			if (!CollectionUtils.isEmpty(this.customClientMetadata)) {
				clientRegistration.getClaims().forEach((claim, value) -> {
					if (this.customClientMetadata.contains(claim)) {
						clientSettingsBuilder.setting(claim, value);
					}
				});
			}

			return RegisteredClient.from(registeredClient).clientSettings(clientSettingsBuilder.build()).build();
		}
	}

	private static class CustomClientRegistrationConverter
			implements Converter<RegisteredClient, OidcClientRegistration> {

		private final List<String> customClientMetadata;
		private final RegisteredClientOidcClientRegistrationConverter delegate;

		private CustomClientRegistrationConverter(List<String> customClientMetadata) {
			this.customClientMetadata = customClientMetadata;
			this.delegate = new RegisteredClientOidcClientRegistrationConverter();
		}

		@Override
		public OidcClientRegistration convert(RegisteredClient registeredClient) {
			OidcClientRegistration clientRegistration = this.delegate.convert(registeredClient);

			Map<String, Object> claims = new HashMap<>();
			if (clientRegistration != null) {
				claims.putAll(clientRegistration.getClaims());
				if (!CollectionUtils.isEmpty(this.customClientMetadata)) {
					ClientSettings clientSettings = registeredClient.getClientSettings();
					claims.putAll(this.customClientMetadata.stream()
							.filter(metadata -> clientSettings.getSetting(metadata) != null)
							.collect(Collectors.toMap(Function.identity(), clientSettings::getSetting)));
				}
			}
			return OidcClientRegistration.withClaims(claims).build();
		}

	}

	@Bean
	JWKSource<SecurityContext> jwkSource() {
		KeyPair keyPair = generateRsaKey();
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
		RSAKey rsaKey = new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(UUID.randomUUID().toString())
				.build();
		JWKSet jwkSet = new JWKSet(rsaKey);
		return new ImmutableJWKSet<>(jwkSet);
	}

	private static KeyPair generateRsaKey() {
		KeyPair keyPair;
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			keyPair = keyPairGenerator.generateKeyPair();
		} catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
		return keyPair;
	}

	@Bean
	JwtDecoder jwtDecoder() {
		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource());
	}

	@Bean
	AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder().build();
	}

	@Bean
	RegisteredClientRepository registeredClientRepository(DataSource dataSource) {
		return new JdbcRegisteredClientRepository(new JdbcTemplate(dataSource));
	}

}

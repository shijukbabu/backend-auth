package com.skb.auth.backend.auth.service;

import java.time.Duration;
import java.time.Instant;
import java.util.Set;
import java.util.UUID;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Service;

import com.skb.auth.backend.auth.payload.request.ClientRequest;

import lombok.AllArgsConstructor;

@Service
@AllArgsConstructor
public class ClientRegistrationService {

	private RegisteredClientRepository registeredClientRepository;

	private PasswordEncoder passwordEncoder;

	public RegisteredClient register(ClientRequest clientRequest) {
		String uuid = UUID.randomUUID().toString();
		Set<ClientAuthenticationMethod> authMethods = Set.of(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
		Set<AuthorizationGrantType> authGrantTypes = Set.of(AuthorizationGrantType.CLIENT_CREDENTIALS,
				AuthorizationGrantType.AUTHORIZATION_CODE, AuthorizationGrantType.REFRESH_TOKEN);
		Set<String> scopes = Set.of("openid", "client.create", "client.read");
		RegisteredClient registeredClient = RegisteredClient.withId(uuid).clientId(clientRequest.getClientId())
				.clientIdIssuedAt(Instant.now()).clientSecret(passwordEncoder.encode(clientRequest.getClientSecret()))
				.clientName(clientRequest.getClientName())
				.clientAuthenticationMethods(clientAuthMethods -> clientAuthMethods.addAll(authMethods))
				.authorizationGrantTypes(grantTypes -> grantTypes.addAll(authGrantTypes))
				.redirectUris(uris -> uris.addAll(clientRequest.getRedirectUris()))
//				.postLogoutRedirectUris(postUris -> postUris.addAll(clientRequest.getPostLogoutRedirectUris()))
				.scopes(scops -> scops.addAll(scopes))
				.tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofHours(1))
						.refreshTokenTimeToLive(Duration.ofDays(1)).build())
				.build();
		registeredClientRepository.save(registeredClient);
		return registeredClient;
	}
}

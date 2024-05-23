package com.skb.auth.backend.auth.init;

import java.util.List;
import java.util.Set;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Component;

import com.skb.auth.backend.auth.enums.EmploymentType;
import com.skb.auth.backend.auth.model.User;
import com.skb.auth.backend.auth.payload.request.ClientRequest;
import com.skb.auth.backend.auth.repository.UserRepository;
import com.skb.auth.backend.auth.service.ClientRegistrationService;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
@AllArgsConstructor
public class DataLoader implements ApplicationRunner {

	private UserRepository userRepository;

	private RegisteredClientRepository registeredClientRepository;

	private ClientRegistrationService clientRegistrationService;

	private PasswordEncoder passwordEncoder;

	@Override
	public void run(ApplicationArguments args) throws Exception {
		log.info("Running initializer");

		List<User> users = userRepository.findAll();
		if (users.isEmpty()) {
			String password = passwordEncoder.encode("Admin@1234");
			User user = User.builder().firstName("John").middleName("D").lastName("Doe").email("johndoe@gmail.com")
					.designation("System Administrator").employmentType(EmploymentType.PERMANENT).enabled(true)
					.accountExpired(false).accountLocked(false).credentialsExpired(false).password(password).build();
			userRepository.save(user);
		}

		String clientName = "Client1";
		String clientId = "client1";
		RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
		if (registeredClient == null) {
			ClientRequest client1 = ClientRequest.builder().clientId(clientId).clientSecret("ClientSecret1234")
					.clientName(clientName).redirectUris(Set.of("http://127.0.0.1:8080/oauth2/code"))
					.postLogoutRedirectUris(Set.of("http://127.0.0.1:8080/logout")).build();
			clientRegistrationService.register(client1);
		}
		log.info("Saved succesfully...");
	}
}

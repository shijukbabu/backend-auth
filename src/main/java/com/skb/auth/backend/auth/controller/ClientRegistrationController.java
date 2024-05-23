package com.skb.auth.backend.auth.controller;

import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.skb.auth.backend.auth.payload.request.ClientRequest;
import com.skb.auth.backend.auth.service.ClientRegistrationService;

import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/clients")
@RequiredArgsConstructor
@AllArgsConstructor
public class ClientRegistrationController {

	private ClientRegistrationService clientRegistrationService;

	@PostMapping("/register")
	public RegisteredClient registerClient(@Valid @RequestBody ClientRequest clientRequest) {
		return clientRegistrationService.register(clientRequest);
	}
}

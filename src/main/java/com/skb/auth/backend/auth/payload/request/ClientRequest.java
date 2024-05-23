package com.skb.auth.backend.auth.payload.request;

import java.util.Set;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class ClientRequest {

	@NotBlank(message = "Client ID is required")
	@Size(max = 100, message = "Client ID must be at most 100 characters long")
	private String clientId;

	@NotBlank(message = "Client Secret is required")
	@Size(max = 200, message = "Client Secret must be at most 200 characters long")
	private String clientSecret;

	@NotBlank(message = "Client Name is required")
	@Size(max = 200, message = "Client Name must be at most 200 characters long")
	private String clientName;

	private Set<@NotBlank(message = "Redirect URI is required") String> redirectUris;

	private Set<@NotBlank(message = "Post Redirect uri is required") String> postLogoutRedirectUris;
}

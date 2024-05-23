package com.skb.auth.backend.auth.payload.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class CreateUser {

	@NotBlank(message = "First name is required")
	private String firstName;

	private String middleName;

	@NotBlank(message = "Last name is required")
	private String lastName;

	@Email(message = "Invalid email format")
	@NotBlank(message = "Email is required")
	private String email;

	@NotBlank(message = "Designation is required")
	private String designation;

	@NotBlank(message = "Password is required")
	private String password;

	@NotBlank(message = "Employment type is required")
	private String employmentType;
}

package com.skb.auth.backend.auth.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.skb.auth.backend.auth.payload.request.CreateUser;
import com.skb.auth.backend.auth.service.UserService;

import lombok.AllArgsConstructor;

@RestController
@RequestMapping("/users")
@AllArgsConstructor
public class UserController {

	private UserService userService;

	@PostMapping
	public ResponseEntity<String> addUser(@Validated @RequestBody CreateUser createUser) {
		userService.addUser(createUser);
		return ResponseEntity.status(HttpStatus.CREATED).body("User added successfully");
	}
}

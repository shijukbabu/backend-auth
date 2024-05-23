package com.skb.auth.backend.auth.service;

import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.skb.auth.backend.auth.model.User;
import com.skb.auth.backend.auth.payload.request.CreateUser;
import com.skb.auth.backend.auth.repository.UserRepository;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
@AllArgsConstructor
public class UserService {

	private UserRepository userRepository;

	private PasswordEncoder passwordEncoder;

	private ModelMapper modelMapper;

	public void addUser(CreateUser createUser) {
		User user = modelMapper.map(createUser, User.class);
		user.setPassword(passwordEncoder.encode(createUser.getPassword()));
		// You may add additional user properties as needed
		log.info("Adding user to DB {}", user);
		userRepository.save(user);
	}
}

package com.skb.auth.backend.auth.security.service;

import java.util.ArrayList;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.skb.auth.backend.auth.model.User;
import com.skb.auth.backend.auth.repository.UserRepository;
import com.skb.auth.backend.auth.security.userdetail.OIDCUserDetails;

import lombok.AllArgsConstructor;

@Service
@AllArgsConstructor
public class AuthService implements UserDetailsService {

	private UserRepository userRepository;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		User user = userRepository.findByEmail(username).orElse(null);
		if (user == null) {
			throw new UsernameNotFoundException("User not found");
		}
		return new OIDCUserDetails(user.getEmail(), user.getPassword(), new ArrayList<>());
	}
}

package br.com.tcc.authorizer.service;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import br.com.tcc.authorizer.security.UserSecurity;

@Service
public class UserSecurityServiceImpl implements UserDetailsService {

	private static final UserDetails DEFAULT_USER_DETAILS = new UserSecurity();
	
	@Override
	public UserDetails loadUserByUsername(String login) throws UsernameNotFoundException {
		return DEFAULT_USER_DETAILS; // not used
	}}

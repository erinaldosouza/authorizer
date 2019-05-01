package br.com.tcc.authorizer.security;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import io.jsonwebtoken.Claims;

public class JWTAuthorizerFilter extends BasicAuthenticationFilter {

	private final JWTUtil jwtUtil;
	private static final String AUTH_PREFIX = "Bearer ";

	@Autowired
	public JWTAuthorizerFilter(	JWTUtil jwtUtil, AuthenticationManager authenticationManager) {
		super(authenticationManager);
		this.jwtUtil = jwtUtil;
	}

	@Override
	@SuppressWarnings("unchecked")
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
		
		try {
			String token = request.getHeader("Authentication");
			String requested = request.getHeader("appname")
									  .concat(request.getHeader("route"))
									  .concat(request.getHeader("method"));
			
			if(StringUtils.isNotBlank(token) && token.startsWith(AUTH_PREFIX)) {
				
				token = token.replace(AUTH_PREFIX, "");
				Claims claims = jwtUtil.getClaims(token);
				
				if(claims != null) {
					
					List<Map<String, String>> autorities = (List<Map<String, String>>)claims.get(jwtUtil.getTokenAuthoritiesKey());
					
					Optional<Map<String, String>> optAuthority = 
													autorities.stream().filter(auth -> {
														return requested.equals(auth.get("authority"));
													}).findFirst();
					
					if(optAuthority.isPresent()) {
						response.getWriter().append(
								"{\"Success\" : \"true\",\"message\" : \"User authorized. \"}");
					} else {
						response.getWriter().append(
								"{\"Success\" : \"true\",\"message\" : \"User unauthorized. \"}");
					}
					
					
				}
			}
		} catch (Exception e) {
			response.getWriter().append(
					"{\"Success\" : \"false\",\"message\" : \"Couldn't authorize the user request. " + e.getMessage() + "\"}");
		}
		
	}
	
	@Override
	protected void onUnsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException failed) throws IOException {

		response.getWriter().append("aaa").flush();

	}
	
}

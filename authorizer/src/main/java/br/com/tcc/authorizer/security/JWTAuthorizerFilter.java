package br.com.tcc.authorizer.security;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;

@Configuration
public class JWTAuthorizerFilter implements Filter {

	private final JWTUtil jwtUtil;
	private static final String AUTH_PREFIX = "Bearer ";

	@Autowired
	public JWTAuthorizerFilter(JWTUtil jwtUtil) {
		this.jwtUtil = jwtUtil;
	}

	@Override
	@SuppressWarnings("unchecked")
	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) res;
		
		try {			

			String route = request.getHeader("route");
			String appname = request.getHeader("appname");
			String httpMethod = request.getHeader("http_method");
			String token = request.getHeader("Authentication");
			response.setContentType(MediaType.APPLICATION_JSON_VALUE);

			if(StringUtils.isNotBlank(token) && token.startsWith(AUTH_PREFIX)
			   && StringUtils.isNotBlank(appname) && StringUtils.isNotBlank(httpMethod) && StringUtils.isNotBlank(route)) {
				
				HttpMethod.valueOf(httpMethod); // throw exception if invalid http method 
				String requested = appname.concat(route).concat(httpMethod);
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
								"{\"success\" : true,\"message\" : \"User authorized. \", \"request_status\": 200}");
					} else {
						response.getWriter().append(
								"{\"success\" : true,\"message\" : \"User unauthorized. \", \"request_status\": 403}");
					}
				}
			} else {
				response.setStatus(HttpStatus.BAD_REQUEST.value());
				response.getWriter().append(
						"{\"success\" : true,\"message\" : \"authentication, appname, route and http_method are required.\", \"request_status\": 401}");
			}
			
		} catch (ExpiredJwtException e) {
			response.getWriter().append(
					"{\"success\" : true,\"message\" : \"Couldn't authorize the user request. " + e.getMessage() + "\", \"request_status\": 403}");
		
		} catch (Exception e) {
			e.printStackTrace();
			response.getWriter().append(
					"{\"success\" : false,\"message\" : \"Couldn't authorize the user request. " + e.getMessage() + "\", \"request_status\": 403}");
		}
		
	}
	
}

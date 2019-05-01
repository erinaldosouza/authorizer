package br.com.tcc.authorizer.security;

import java.util.Date;

import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

@Component
public class JWTUtil {
	
	@Value("${jwt.secret}")
	private String secret;
	
	@Value("${jwt.token.authorities.key}")
	private String tokenAuthoritiesKey;
	
	
	public String getUsername(String token) {
		String username = null;
		Claims claims = getClaims(token);
		
		if (claims != null) {
			username = claims.getSubject();
		}
		
		return username;
	}
	
	public boolean isValid(String token) {
		
		boolean isValid = Boolean.FALSE;
		Claims claims = getClaims(token);
		
		if(claims != null) {
			Date now = new Date();			
			Date expirationDate = claims.getExpiration();
			isValid = (StringUtils.isNotBlank(claims.getSubject()) && expirationDate != null && now.before(expirationDate));
		}
		
		return isValid;
	}

	public Claims getClaims(String token) {
		return Jwts.parser().setSigningKey(secret.getBytes()).parseClaimsJws(token).getBody();
	}
	
	public String getTokenAuthoritiesKey() {
		return this.tokenAuthoritiesKey;
	}

}

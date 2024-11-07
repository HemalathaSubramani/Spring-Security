package com.demo.security.service;

import java.util.Date;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.demo.security.models.AppUser;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {
	
	@Value("${security.jwt.secret-key}")
	private String secretKey;
	@Value("${security.jwt.expiration-time-ms}")
	private long expirationTimeMs;
	@Value("${security.jwt.issuer}")
	private String isuser;//new jwt dependencies added in pom.xml by copying from github
	
	
	public String createJwtToken(AppUser user) {
		byte[] keyBytes = Decoders.BASE64.decode(secretKey);
		var Key = Keys.hmacShaKeyFor(keyBytes);
		
		return Jwts
				.builder()
				.subject(user.getEmail())
				.issuedAt(new Date(System.currentTimeMillis()))
				.issuer(isuser)
				.expiration(new Date(System.currentTimeMillis() + expirationTimeMs))
				.signWith(Key).compact();
	}
	
	public Claims getTokenClaims(String token) {//if token is invalid or it got expired this method will run
		byte[]  KeyBytes = Decoders.BASE64.decode(secretKey);
		var Key = Keys.hmacShaKeyFor(KeyBytes);
		
		try {
			var claims =Jwts.parser().verifyWith(Key)
					.build()
					.parseSignedClaims(token)
					.getPayload();
			
			Date expDate = claims.getExpiration();
			Date currentDate = new Date();
			if(currentDate.before(expDate)) {
				return claims;
			}
		}
		catch(Exception ex) {
			
		}
		return null;
	}

}

package com.demo.security.service;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.web.filter.OncePerRequestFilter;

import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Service
public class JwtAuthenticationFilter extends OncePerRequestFilter {
	
	
	//these two autowired is for check the token is valid or not
	@Autowired
	private JwtService jwtService;
	@Autowired
	private AppUserService appUserService;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		
		//this is to check this jwttoken is valid or not
		
		try {//token always starts with bearerso put conditin to check accordibg to that
			String bearerToken = request.getHeader("Authorization");
			
			if(bearerToken == null || !bearerToken.startsWith("Bearer")) {
				throw new Exception("Authorization Bearer not Found");
			}
			
			String jwt = bearerToken.substring(7);//and we removing that bearer prefix
			Claims claims = jwtService.getTokenClaims(jwt);
			
			if(claims == null) {
				throw new Exception("Token is not valid");
			}
			//if the jwttoken is valid this will happen
			String email = claims.getSubject();
			var userDetails = appUserService.loadUserByUsername(email);
			
			UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, null);
			SecurityContextHolder.getContext().setAuthentication(authentication);
			
		}
		catch(Exception e)
		{
			e.printStackTrace();
		}
			
		filterChain.doFilter(request, response);//filter chain for filter user
		//after this go to security config for filter request
	}

}

package com.demo.security.controller;

import java.util.Date;
import java.util.HashMap;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.*;

import com.demo.security.models.AppUser;
import com.demo.security.models.LoginDto;
import com.demo.security.models.RegisterDto;
import com.demo.security.repository.AppUserRepository;
import com.demo.security.service.JwtService;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/account")
public class AccountController {
	
	@Autowired
	private AppUserRepository appUserRepository;
	
	@Autowired
	private JwtService jwtservice;
	
	@Autowired//for authenticateso paste the token and send in postman
	private AuthenticationManager authenticationManager;//*authenticate who the user is and checks with db and verifies the pass and user validates
	
	@GetMapping("/profile")
	public ResponseEntity<Object> profile(Authentication auth)
	{
		var repsonse= new HashMap<String, Object>();
		repsonse.put("Username", auth.getName());//these two to display in postman with same name 
		repsonse.put("Authorites", auth.getAuthorities());
		
		var appUser = appUserRepository.findByEmail(auth.getName());
		repsonse.put("User", appUser);//these same user will send in postman
		
		return ResponseEntity.ok(repsonse);
	}
	
	@PostMapping("/register")//through this the first time user details stored in db and take and coming 1
	public ResponseEntity<Object> register(@Valid @RequestBody RegisterDto registerDto, BindingResult result){
		if(result.hasErrors()) {//to display errormsg
			var errorList = result.getAllErrors();
			var errorMap = new HashMap<String, String>();
			for(int i=0 ; i < errorList.size() ; i++) {
				var error = (FieldError) errorList.get(i);
				errorMap.put(error.getField(), error.getDefaultMessage());
			}
			return ResponseEntity.badRequest().body(errorMap);
		}
		
		AppUser appUser = new AppUser();//this is how it will display in the postman return
		appUser.setFirstName(registerDto.getFirstName());
		appUser.setLastName(registerDto.getLastName());
		appUser.setEmail(registerDto.getEmail());
		appUser.setPhone(registerDto.getPhone());
		appUser.setAddress(registerDto.getAddress());
		appUser.setRole("client");
		appUser.setCreatedAt(new Date());
		
		var bCryptEncoder = new BCryptPasswordEncoder();
		appUser.setPassword(bCryptEncoder.encode(registerDto.getPassword()));//this generates and sets passwod in db and retunrs in postman
		
		try {
			var otherUser = appUserRepository.findByEmail(registerDto.getEmail());
			if(otherUser != null) {
				return ResponseEntity.badRequest().body("Email address already used");
			}
			appUserRepository.save(appUser);
			
			String jwtToken = jwtservice.createJwtToken(appUser);
			
			var response = new  HashMap<String, Object>();
			response.put("token", jwtToken);
			response.put("user", appUser);
			
			return ResponseEntity.ok(response);
		}
		catch(Exception ex)
		{
			ex.printStackTrace();
		}
		
		return ResponseEntity.badRequest().body("Error");
	}
	
	
	@PostMapping("/login")
	private ResponseEntity<Object> login(@Valid @RequestBody LoginDto loginDto, BindingResult result){
		
		if(result.hasErrors()) {//checking it has any error or not
			var errorList = result.getAllErrors();
			var errorMap = new HashMap<String, String>();
			
			for(int i=0 ; i < errorList.size() ; i++) {
				var error = (FieldError) errorList.get(i);
				errorMap.put(error.getField(), error.getDefaultMessage());
			}
			return ResponseEntity.badRequest().body(errorMap);
		}
		
		try {
			authenticationManager.authenticate(//authentication username and password is correct or not if its crct server checks an generate token
					new UsernamePasswordAuthenticationToken
					(
							loginDto.getEmail(),
							loginDto.getPassword()
							)
					);
			//these down and all returning from db too present in postman reponse
			AppUser appUser = appUserRepository.findByEmail(loginDto.getEmail());
			
			String jwtToken = jwtservice.createJwtToken(appUser);
			
			var response = new  HashMap<String, Object>();
			response.put("token", jwtToken);//the first string isdisplay in db by bundle it upand second one is
			response.put("user", appUser); 
			
			return ResponseEntity.ok(response);
		}
		catch(Exception e) {
			System.out.println("There is an Exception");
			e.printStackTrace();
		}
		
		return ResponseEntity.badRequest().body("Bad username or password");
		
	}

}

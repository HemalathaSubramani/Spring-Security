package com.demo.security.models;

import jakarta.validation.constraints.*;

public class LoginDto {
	
	
	@NotEmpty
	@Email
	private String email;
	
	@NotEmpty
	private String password;

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}
	
	

}

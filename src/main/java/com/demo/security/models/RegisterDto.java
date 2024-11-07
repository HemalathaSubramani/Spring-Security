package com.demo.security.models;

import jakarta.validation.constraints.*;

public class RegisterDto {//usually dto is for postman bodys param the user have to send and they taken and come all complex toan single form

	@NotEmpty
	private String firstName;
	@NotEmpty
	private String lastName;
	@NotEmpty
	@Email
	private String email;
	private String phone;
	private String address;
	@NotEmpty
	@Size(min = 6, message = "Minimum password length is 6 characters")
	private String password;
	public String getFirstName() {
		return firstName;
	}
	public void setFirstName(String firstName) {
		this.firstName = firstName;
	}
	public String getLastName() {
		return lastName;
	}
	public void setLastName(String lastName) {
		this.lastName = lastName;
	}
	public String getEmail() {
		return email;
	}
	public void setEmail(String email) {
		this.email = email;
	}
	public String getPhone() {
		return phone;
	}
	public void setPhone(String phone) {
		this.phone = phone;
	}
	public String getAddress() {
		return address;
	}
	public void setAddress(String address) {
		this.address = address;
	}
	public String getPassword() {
		return password;
	}
	public void setPassword(String password) {
		this.password = password;
	}
	
	
	
}

package com.demo.security.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {
	
	@GetMapping("/")
	public String home() {
		return "Home Page";
	}
	
	@GetMapping("/store")
	public String store() {
		return "Store Page";
	}

}

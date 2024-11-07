package com.demo.security.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.demo.security.models.AppUser;

@Repository
public interface AppUserRepository extends JpaRepository<AppUser, Integer>{
	
	public AppUser findByEmail(String email);

}

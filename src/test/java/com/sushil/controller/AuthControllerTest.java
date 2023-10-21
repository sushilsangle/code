package com.sushil.controller;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.junit.jupiter.api.Assertions.*;


@RestController
@SpringBootTest
@RequestMapping("/api/test")
class AuthControllerTest {

    @GetMapping("/all")
    public String getAll(){
        return "Public Content.";
    }
    @GetMapping("/user")
    @PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasAdmin('ADMIN')")
    public String userAccess(){
        return "User Content";
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('Admin')")
    public String adminAccess(){
        return "Admin Content";
    }
    @GetMapping("/mod")
    @PreAuthorize("hasRole('Mod')")
    public String modAccess(){
        return "Mod Content";
    }


}
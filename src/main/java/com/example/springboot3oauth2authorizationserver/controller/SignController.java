package com.example.springboot3oauth2authorizationserver.controller;

import com.example.springboot3oauth2authorizationserver.config.DatabaseLoader;
import com.example.springboot3oauth2authorizationserver.dto.JoinDto;
import com.example.springboot3oauth2authorizationserver.entity.Role;
import com.example.springboot3oauth2authorizationserver.entity.User;
import com.example.springboot3oauth2authorizationserver.security.CustomUserPrincipal;
import com.example.springboot3oauth2authorizationserver.security.JpaUserDetailsManager;
import com.example.springboot3oauth2authorizationserver.service.JoinService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
public class SignController {

    private final JoinService joinService;

    @PostMapping("join")
    public User join(@RequestBody JoinDto joinDto){
        return joinService.save(joinDto);
    }


}

package com.example.springboot3oauth2authorizationserver.controller;

import com.example.springboot3oauth2authorizationserver.dto.JoinDto;
import com.example.springboot3oauth2authorizationserver.entity.User;
import com.example.springboot3oauth2authorizationserver.service.JoinService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class SignController {

    private final JoinService joinService;

    @PostMapping("join")
    public User join(@RequestBody JoinDto joinDto){
        return joinService.save(joinDto);
    }


}

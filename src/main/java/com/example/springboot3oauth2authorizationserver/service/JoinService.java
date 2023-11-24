package com.example.springboot3oauth2authorizationserver.service;

import com.example.springboot3oauth2authorizationserver.dto.JoinDto;
import com.example.springboot3oauth2authorizationserver.entity.Role;
import com.example.springboot3oauth2authorizationserver.entity.User;
import com.example.springboot3oauth2authorizationserver.repository.RoleRepository;
import com.example.springboot3oauth2authorizationserver.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class JoinService {

    private final UserRepository userRepository;
    private final RoleRepository repository;
    private final PasswordEncoder passwordEncoder;


    public User save(JoinDto joinDto){
        Role roleUser = repository.findByName("ROLE_USER").orElseThrow(() -> new IllegalArgumentException("no role"));


        return userRepository.save(User.builder()
                        .username(joinDto.getUsername())
                         .password(passwordEncoder.encode(joinDto.getPassword()))
                         .role(roleUser)
                         .active(Boolean.TRUE).build());

    }

}

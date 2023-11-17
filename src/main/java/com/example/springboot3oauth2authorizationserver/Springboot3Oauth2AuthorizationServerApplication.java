package com.example.springboot3oauth2authorizationserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.util.TimeZone;

@SpringBootApplication
public class Springboot3Oauth2AuthorizationServerApplication {

    public static void main(String[] args) {
        TimeZone.setDefault(TimeZone.getTimeZone("KST"));
        SpringApplication.run(Springboot3Oauth2AuthorizationServerApplication.class, args);
    }

}

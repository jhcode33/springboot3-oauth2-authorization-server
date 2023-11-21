package com.example.springboot3oauth2authorizationserver.dto;

import com.example.springboot3oauth2authorizationserver.entity.Role;
import lombok.Builder;
import lombok.Getter;
import lombok.ToString;

@Getter
@ToString
@Builder
public class JoinDto {

    private Long id;

//    @Pattern(regexp = "^([0-9a-zA-Z_\\.-]+)@([0-9a-zA-Z_-]+)(\\.[0-9a-zA-Z_-]+){1,2}$" , message = "올바른 이메일 형식이 아닙니다")
    private String username;

    private String password;

    /*private String name;

    @Pattern(regexp = "^01([0|1|6|7|8|9])-?([0-9]{3,4})-?([0-9]{4})$", message = "휴대폰번호를 확인해 주세요")
    private String phoneNumber;*/

    /*private String role;

    private String active;*/

}

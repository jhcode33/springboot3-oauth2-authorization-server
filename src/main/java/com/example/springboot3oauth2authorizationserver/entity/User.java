package com.example.springboot3oauth2authorizationserver.entity;

import jakarta.persistence.*;
import lombok.Data;
import lombok.EqualsAndHashCode;
import org.springframework.context.annotation.Configuration;

/**
 * 회원 가입 된 사용자 entity
 */
@Entity
@Data
// Lombok을 사용하여 equals()와 hashCode() 메서드를 생성하며, callSuper = true는 부모 클래스인 AbstractEntity의 필드도 고려하여 생성
@EqualsAndHashCode(callSuper = true)
public class User extends AbstractEntity {

    // 아이디 = email
    @Column(name = "username", nullable = false)
    private String username;

    // 비밀번호
    @Column(name = "password", nullable = false)
    private String password;

    // 권한
    @ManyToOne(optional = false, fetch = FetchType.EAGER)
    @JoinColumn(name = "role_id")
    private Role role;

    // 활성화 여부
    @Column(name = "active")
    private Boolean active;

}

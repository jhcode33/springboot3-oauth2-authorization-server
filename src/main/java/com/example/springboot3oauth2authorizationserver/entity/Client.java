package com.example.springboot3oauth2authorizationserver.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import lombok.Data;

import java.time.Instant;

/**
 * Client 정보를 등록하는 Entity
 */
@Entity
@Data
public class Client {

    // PK
    @Id
    private String id;

    // 클라이언트 아이디
    @Column(unique = true)
    private String clientId;

    // 클라이언트 비밀번호
    private String clientSecret;

    // 클라이언트 id가 발급된 시간
    private Instant clientIdIssuedAt;

    // 클라이언트 비밀 key의 만료 시간
    private Instant clientSecretExpiresAt;

    // 클라이언트의 이름
    private String clientName;

    // 클라이언트 인증 방법
    @Column(length = 1000)
    private String clientAuthenticationMethods;

    // 클라이언트가 요청할 수 있는 권한 부여 유형(Grant Type: authorization_code 등)
    @Column(length = 1000)
    private String authorizationGrantTypes;

    // 리다이렉트 URI -> authorization_code, Access Token이 전달될 경로
    @Column(length = 1000)
    private String redirectUris;

    // 로그 아웃 후에 리다이렉트될 URI
    @Column(length = 1000)
    private String postLogoutRedirectUris;

    // 클라이언트가 요청할 수 있는 정보에 대한 권한
    @Column(length = 1000)
    private String scopes;

    // 클라이언트 추가 설정
    @Column(length = 2000)
    private String clientSettings;

    // 클라이언트 토큰 설정
    @Column(length = 2000)
    private String tokenSettings;
}

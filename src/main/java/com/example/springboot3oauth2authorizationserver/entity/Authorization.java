package com.example.springboot3oauth2authorizationserver.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import lombok.Data;

import java.time.Instant;

/**
 * 인증된 사용자에게 반환한 권한에 대한 정보를 저장하는 Entity
 */
@Entity
@Data
public class Authorization {

    // PK
    @Id
    private String id;

    // 권한을 요청한 Client의 ID
    private String registeredClientId;

    // 권한을 부여받은 주체(Principal)의 이름 : 사용자(User) 식별 정보
    private String principalName;

    // 권한 부여 유형 (authorization_code, implicit 등)
    private String authorizationGrantType;

    // scope
    @Column(length = 1000)
    private String authorizedScopes;

    // 권한과 관련된 추가 속성을 저장하는데 사용되는 텍스트 형식의 필드
    @Column(columnDefinition="TEXT")
    private String attributes;

    // 상태 정보
    @Column(length = 500)
    private String state;

    // Authorization Code 값을 저장하는 필드
    @Column(columnDefinition="TEXT")
    private String authorizationCodeValue;

    // Authorization Code 발급 시간
    private Instant authorizationCodeIssuedAt;

    // Authorization Code 만료 시간
    private Instant authorizationCodeExpiresAt;

    // Authorization Code에 대한 메타데이터를 저장하는 필드
    @Column(columnDefinition="TEXT")
    private String authorizationCodeMetadata;

    // Access Token
    @Column(columnDefinition="TEXT")
    private String accessTokenValue;

    // Access Token 발급 시간
    private Instant accessTokenIssuedAt;

    // Access Token 만료 시간
    private Instant accessTokenExpiresAt;

    // Access Token의 메타 데이터를 저장하는 필드
    @Column(columnDefinition="TEXT")
    private String accessTokenMetadata;

    // Access Token 타입
    private String accessTokenType;

    // Access Token 스코프(권한)
    @Column(columnDefinition="TEXT")
    private String accessTokenScopes;

    // Refresh Token
    @Column(columnDefinition="TEXT")
    private String refreshTokenValue;

    // Refresh Token 발급 시간
    private Instant refreshTokenIssuedAt;

    // Refresh Token 만료 시간
    private Instant refreshTokenExpiresAt;

    // Refresh Token 메타 데이터
    @Column(columnDefinition="TEXT")
    private String refreshTokenMetadata;

    //== 아래는 필요할 경우 사용 ==//
//    // OpenId Connect ID Token
//    @Column(columnDefinition="TEXT")
//    private String oidcIdTokenValue;

//    // OpenId Connect Id Token 발급 시간
//    private Instant oidcIdTokenIssuedAt;
//
//    // OpenId Connect Id Token 만료 시간
//    private Instant oidcIdTokenExpiresAt;
//
//    // OpenId Connect Id Token 메타 데이터 저장 필드
//    @Column(columnDefinition="TEXT")
//    private String oidcIdTokenMetadata;
//
//    // OpenId Connect Id Token 클레임(주장: 사용자 이름, 이메일 등 어떤 정보에 접근할 수 있는지에 대한 정보)
//    @Column(columnDefinition="TEXT")
//    private String oidcIdTokenClaims;

//    @Column(length = 4000)
//    private String userCodeValue;
//    private Instant userCodeIssuedAt;
//    private Instant userCodeExpiresAt;
//    @Column(length = 2000)
//    private String userCodeMetadata;
//
//    @Column(length = 4000)
//    private String deviceCodeValue;
//    private Instant deviceCodeIssuedAt;
//    private Instant deviceCodeExpiresAt;
//    @Column(length = 2000)
//    private String deviceCodeMetadata;
}

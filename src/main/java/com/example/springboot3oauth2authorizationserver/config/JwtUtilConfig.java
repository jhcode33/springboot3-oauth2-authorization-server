package com.example.springboot3oauth2authorizationserver.config;

import com.example.springboot3oauth2authorizationserver.jose.Jwks;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;

@Configuration
public class JwtUtilConfig {

    /**
     * JwtEncoder
     * @param jwkSource
     * @return
     * @author jhcode33
     * @Date 2023.11.16
     */
    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }

    // jwtDecoder를 구현한 NimbusJwtDecoder는
    // Authorization Server에서 발급한 JWT 토큰을 편리하게 디코딩하고, 서명을 확인하며, 클레임을 추출 한다.
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    // RSA는 암호화 뿐만 아니라 전자서명이 가능한 알고리즘이다.
    // RSA 알고리즘을 사용한 JWK를 생성하고 JWKSet으로 묶어서 제공
    // 이 JWKSet은 jwkSelector와 securityContext를 인자로 받아서 선택된 JWK를 반환함.
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAKey rsaKey = Jwks.generateRsa();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }
}

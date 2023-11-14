package com.example.springboot3oauth2authorizationserver.service;

import com.example.springboot3oauth2authorizationserver.entity.AuthorizationConsent;
import com.example.springboot3oauth2authorizationserver.repository.AuthorizationConsentRepository;
import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.authorization.*;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.util.HashSet;
import java.util.Set;

/**
 * 사용자가 클라이언트에게 권한을 부여한 내용을 처리
 * @implements OAuth2AuthorizationConsentService
 */
@Component
public class JpaOAuth2AuthorizationConsentService implements OAuth2AuthorizationConsentService {

    private final AuthorizationConsentRepository authorizationConsentRepository;
    private final RegisteredClientRepository registeredClientRepository;

    public JpaOAuth2AuthorizationConsentService(AuthorizationConsentRepository authorizationConsentRepository, RegisteredClientRepository registeredClientRepository) {
        Assert.notNull(authorizationConsentRepository, "authorizationConsentRepository cannot be null");
        Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
        this.authorizationConsentRepository = authorizationConsentRepository;
        this.registeredClientRepository = registeredClientRepository;
    }

    @Override
    public void save(OAuth2AuthorizationConsent authorizationConsent) {
        Assert.notNull(authorizationConsent, "authorizationConsent cannot be null");
        this.authorizationConsentRepository.save(toEntity(authorizationConsent));
    }

    @Override
    public void remove(OAuth2AuthorizationConsent authorizationConsent) {
        Assert.notNull(authorizationConsent, "authorizationConsent cannot be null");
        this.authorizationConsentRepository.deleteByRegisteredClientIdAndPrincipalName(
                authorizationConsent.getRegisteredClientId(), authorizationConsent.getPrincipalName());
    }

    @Override
    public OAuth2AuthorizationConsent findById(String registeredClientId, String principalName) {
        Assert.hasText(registeredClientId, "registeredClientId cannot be empty");
        Assert.hasText(principalName, "principalName cannot be empty");
        return this.authorizationConsentRepository.findByRegisteredClientIdAndPrincipalName(
                registeredClientId, principalName).map(this::toObject).orElse(null);
    }

    /**
     * AuthorizationConsent 엔티티를 OAuth2AuthorizationConsent 객체로 변환하는 메소드
     * @param authorizationConsent
     * @return OAuth2AuthorizationConsent
     */
    private OAuth2AuthorizationConsent toObject(AuthorizationConsent authorizationConsent) {
        // AuthorizationConsent 엔터티로부터 등록된 클라이언트 ID를 가져옴
        String registeredClientId = authorizationConsent.getRegisteredClientId();

        // 클라이언트 ID를 사용하여 RegisteredClient를 데이터베이스에서 조회
        RegisteredClient registeredClient = this.registeredClientRepository.findById(registeredClientId);

        // 등록된 클라이언트가 존재하지 않으면 예외 발생
        if (registeredClient == null) {
            throw new DataRetrievalFailureException(
                    "The RegisteredClient with id '" + registeredClientId + "' was not found in the RegisteredClientRepository.");
        }

        // OAuth2AuthorizationConsent.Builder를 사용하여 OAuth2AuthorizationConsent 객체 생성
        OAuth2AuthorizationConsent.Builder builder =
                OAuth2AuthorizationConsent.withId(registeredClientId, authorizationConsent.getPrincipalName());

        // AuthorizationConsent에 포함된 권한(authorities)을 가져와서 OAuth2AuthorizationConsent에 추가
        if (authorizationConsent.getAuthorities() != null) {
            for (String authority : StringUtils.commaDelimitedListToSet(authorizationConsent.getAuthorities())) {
                builder.authority(new SimpleGrantedAuthority(authority));
            }
        }

        return builder.build();
    }

    /**
     * OAuth2AuthorizationConsent 객체를 AuthorizationConsent 엔티티로 변환하는 메소드
     * @param oAuth2AuthorizationConsent
     * @return AuthorizationConsent
     */
    private AuthorizationConsent toEntity(OAuth2AuthorizationConsent oAuth2AuthorizationConsent) {
        AuthorizationConsent entity = new AuthorizationConsent();
        entity.setRegisteredClientId(oAuth2AuthorizationConsent.getRegisteredClientId());     // 클라이언트 ID
        entity.setPrincipalName(oAuth2AuthorizationConsent.getPrincipalName());               // 인증 주체

        // 권한 설정
        Set<String> authorities = new HashSet<>();
        for (GrantedAuthority authority : oAuth2AuthorizationConsent.getAuthorities()) {
            authorities.add(authority.getAuthority());
        }
        entity.setAuthorities(StringUtils.collectionToCommaDelimitedString(authorities));

        return entity;
    }
}

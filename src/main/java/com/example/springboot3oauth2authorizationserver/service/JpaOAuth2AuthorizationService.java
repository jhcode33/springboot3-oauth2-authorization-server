package com.example.springboot3oauth2authorizationserver.service;

import com.example.springboot3oauth2authorizationserver.entity.Authorization;
import com.example.springboot3oauth2authorizationserver.repository.AuthorizationRepository;
import com.example.springboot3oauth2authorizationserver.security.CustomUserPrincipalMixin;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.nio.file.attribute.UserPrincipal;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;

@Component
public class JpaOAuth2AuthorizationService implements OAuth2AuthorizationService {

    private final AuthorizationRepository authorizationRepository;
    private final RegisteredClientRepository registeredClientRepository;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public JpaOAuth2AuthorizationService(AuthorizationRepository authorizationRepository, RegisteredClientRepository registeredClientRepository) {
        Assert.notNull(authorizationRepository, "authorizationRepository cannot be null");
        Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
        this.authorizationRepository = authorizationRepository;
        this.registeredClientRepository = registeredClientRepository;

        ClassLoader classLoader = JpaOAuth2AuthorizationService.class.getClassLoader();
        List<Module> securityModules = SecurityJackson2Modules.getModules(classLoader);
        this.objectMapper.registerModules(securityModules);
        this.objectMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());

        // Test 중
        //this.objectMapper.registerModule(new CoreJackson2Module());
        this.objectMapper.addMixIn(UserPrincipal.class, CustomUserPrincipalMixin.class);

    }

    @Override
    public void save(OAuth2Authorization authorization) {
        Assert.notNull(authorization, "authorization cannot be null");
        this.authorizationRepository.save(toEntity(authorization));
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        Assert.notNull(authorization, "authorization cannot be null");
        this.authorizationRepository.deleteById(authorization.getId());
    }

    @Override
    public OAuth2Authorization findById(String id) {
        Assert.hasText(id, "id cannot be empty");
        return this.authorizationRepository.findById(id).map(this::toObject).orElse(null);
    }

    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        Assert.hasText(token, "token cannot be empty");

        // Token 정보를 사용해서 DB에 Authorization 엔티티를 조회 -> OAuth2Authorization 객체로 변환하는 메소드
        Optional<Authorization> result;
        if (tokenType == null) {
            result = this.authorizationRepository.findByStateOrAuthorizationCodeValueOrAccessTokenValueOrRefreshTokenValueOrOidcIdTokenValueOrUserCodeValueOrDeviceCodeValue(token);
        } else if (OAuth2ParameterNames.STATE.equals(tokenType.getValue())) {
            result = this.authorizationRepository.findByState(token);
        } else if (OAuth2ParameterNames.CODE.equals(tokenType.getValue())) {
            result = this.authorizationRepository.findByAuthorizationCodeValue(token);
        } else if (OAuth2ParameterNames.ACCESS_TOKEN.equals(tokenType.getValue())) {
            result = this.authorizationRepository.findByAccessTokenValue(token);
        } else if (OAuth2ParameterNames.REFRESH_TOKEN.equals(tokenType.getValue())) {
            result = this.authorizationRepository.findByRefreshTokenValue(token);

//== 현재는 사용하지 않음 ==//
//        } else if (OidcParameterNames.ID_TOKEN.equals(tokenType.getValue())) {
//            result = this.authorizationRepository.findByOidcIdTokenValue(token);
//        } else if (OAuth2ParameterNames.USER_CODE.equals(tokenType.getValue())) {
//            result = this.authorizationRepository.findByUserCodeValue(token);
//        } else if (OAuth2ParameterNames.DEVICE_CODE.equals(tokenType.getValue())) {
//            result = this.authorizationRepository.findByDeviceCodeValue(token);
        } else {
            result = Optional.empty();
        }

        return result.map(this::toObject).orElse(null);
    }

    /**
     * Authorization 엔티티를 OAuth2Authorization 객체로 변환하는 메소드
     * @param entity
     * @return
     */
    private OAuth2Authorization toObject(Authorization entity) {
        // 등록된 클라이언트 조회
        RegisteredClient registeredClient =
                this.registeredClientRepository.findById(entity.getRegisteredClientId());
        if (registeredClient == null) {
            throw new DataRetrievalFailureException(
                    "The RegisteredClient with id '" + entity.getRegisteredClientId() + "' was not found in the RegisteredClientRepository.");
        }

        // OAuth2Authorization 객체 생성
        OAuth2Authorization.Builder builder = OAuth2Authorization
                .withRegisteredClient(registeredClient)                                                        // 등록된 Client 정보
                .id(entity.getId())                                                                            // 등록된 Client Id
                .principalName(entity.getPrincipalName())                                                      // 주체 정보
                .authorizationGrantType(resolveAuthorizationGrantType(entity.getAuthorizationGrantType()))     // 권한 정보
                .authorizedScopes(StringUtils.commaDelimitedListToSet(entity.getAuthorizedScopes()))           // 허용된 스코프
                .attributes(attributes -> attributes.putAll(parseMap(entity.getAttributes())));                // 속성 정보

        // 상태 정보 설정
        if (entity.getState() != null) {
            builder.attribute(OAuth2ParameterNames.STATE, entity.getState());
        }

        // 인가 코드에 대한 정보 저장
        if (entity.getAuthorizationCodeValue() != null) {
            OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(
                    entity.getAuthorizationCodeValue(),
                    entity.getAuthorizationCodeIssuedAt(),
                    entity.getAuthorizationCodeExpiresAt());
            builder.token(authorizationCode, metadata -> metadata.putAll(parseMap(entity.getAuthorizationCodeMetadata())));
        }

        // 엑세스 토큰에 대한 정보 저장
        if (entity.getAccessTokenValue() != null) {
            OAuth2AccessToken accessToken = new OAuth2AccessToken(
                    OAuth2AccessToken.TokenType.BEARER,
                    entity.getAccessTokenValue(),
                    entity.getAccessTokenIssuedAt(),
                    entity.getAccessTokenExpiresAt(),
                    StringUtils.commaDelimitedListToSet(entity.getAccessTokenScopes()));
            builder.token(accessToken, metadata -> metadata.putAll(parseMap(entity.getAccessTokenMetadata())));
        }

        // 리프레시 토큰에 대한 정보 저장
        if (entity.getRefreshTokenValue() != null) {
            OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(
                    entity.getRefreshTokenValue(),
                    entity.getRefreshTokenIssuedAt(),
                    entity.getRefreshTokenExpiresAt());
            builder.token(refreshToken, metadata -> metadata.putAll(parseMap(entity.getRefreshTokenMetadata())));
        }

        //== Open Id ==//
        if (entity.getOidcIdTokenValue() != null) {
            OidcIdToken idToken = new OidcIdToken(
                    entity.getOidcIdTokenValue(),
                    entity.getOidcIdTokenIssuedAt(),
                    entity.getOidcIdTokenExpiresAt(),
                    parseMap(entity.getOidcIdTokenClaims()));
            builder.token(idToken, metadata -> metadata.putAll(parseMap(entity.getOidcIdTokenMetadata())));
        }
//
//        if (entity.getUserCodeValue() != null) {
//            OAuth2UserCode userCode = new OAuth2UserCode(
//                    entity.getUserCodeValue(),
//                    entity.getUserCodeIssuedAt(),
//                    entity.getUserCodeExpiresAt());
//            builder.token(userCode, metadata -> metadata.putAll(parseMap(entity.getUserCodeMetadata())));
//        }
//
//        if (entity.getDeviceCodeValue() != null) {
//            OAuth2DeviceCode deviceCode = new OAuth2DeviceCode(
//                    entity.getDeviceCodeValue(),
//                    entity.getDeviceCodeIssuedAt(),
//                    entity.getDeviceCodeExpiresAt());
//            builder.token(deviceCode, metadata -> metadata.putAll(parseMap(entity.getDeviceCodeMetadata())));
//        }

        return builder.build();
    }

    /**
     * OAuth2Authorization 객체를 Authorization 엔티티로 변환하는 메소드
     * @param authorization
     * @return
     */
    private Authorization toEntity(OAuth2Authorization authorization) {
        Authorization entity = new Authorization();
        entity.setId(authorization.getId());                                                    // OAuth 2.0 인가의 식별자
        entity.setRegisteredClientId(authorization.getRegisteredClientId());                    // 클라이언트 식별자
        entity.setPrincipalName(authorization.getPrincipalName());                              // 주체(principal)의 이름
        entity.setAuthorizationGrantType(authorization.getAuthorizationGrantType().getValue()); // 인가 유형
        entity.setAuthorizedScopes(StringUtils.collectionToDelimitedString(authorization.getAuthorizedScopes(), ",")); // 허용된 스코프
        entity.setAttributes(writeMap(authorization.getAttributes()));                          // 속성 정보
        entity.setState(authorization.getAttribute(OAuth2ParameterNames.STATE));                // 상태 정보

        // 인가 코드에 대한 정보 설정
        OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode =
                authorization.getToken(OAuth2AuthorizationCode.class);
        setTokenValues(
                authorizationCode,
                entity::setAuthorizationCodeValue,
                entity::setAuthorizationCodeIssuedAt,
                entity::setAuthorizationCodeExpiresAt,
                entity::setAuthorizationCodeMetadata
        );

        // 액세스 토큰에 대한 정보 설정
        OAuth2Authorization.Token<OAuth2AccessToken> accessToken =
                authorization.getToken(OAuth2AccessToken.class);
        setTokenValues(
                accessToken,
                entity::setAccessTokenValue,
                entity::setAccessTokenIssuedAt,
                entity::setAccessTokenExpiresAt,
                entity::setAccessTokenMetadata
        );

        // 엑세스 토큰 스코프 설정
        if (accessToken != null && accessToken.getToken().getScopes() != null) {
            entity.setAccessTokenScopes(StringUtils.collectionToDelimitedString(accessToken.getToken().getScopes(), ","));
        }

        // 리프레시 토큰에 대한 정보 설정
        OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken =
                authorization.getToken(OAuth2RefreshToken.class);
        setTokenValues(
                refreshToken,
                entity::setRefreshTokenValue,
                entity::setRefreshTokenIssuedAt,
                entity::setRefreshTokenExpiresAt,
                entity::setRefreshTokenMetadata
        );

        //== ID Token ==//
        OAuth2Authorization.Token<OidcIdToken> oidcIdToken =
                authorization.getToken(OidcIdToken.class);
        setTokenValues(
                oidcIdToken,
                entity::setOidcIdTokenValue,
                entity::setOidcIdTokenIssuedAt,
                entity::setOidcIdTokenExpiresAt,
                entity::setOidcIdTokenMetadata
        );
        if (oidcIdToken != null) {
            entity.setOidcIdTokenClaims(writeMap(oidcIdToken.getClaims()));
        }
//
//        OAuth2Authorization.Token<OAuth2UserCode> userCode =
//                authorization.getToken(OAuth2UserCode.class);
//        setTokenValues(
//                userCode,
//                entity::setUserCodeValue,
//                entity::setUserCodeIssuedAt,
//                entity::setUserCodeExpiresAt,
//                entity::setUserCodeMetadata
//        );
//
//        OAuth2Authorization.Token<OAuth2DeviceCode> deviceCode =
//                authorization.getToken(OAuth2DeviceCode.class);
//        setTokenValues(
//                deviceCode,
//                entity::setDeviceCodeValue,
//                entity::setDeviceCodeIssuedAt,
//                entity::setDeviceCodeExpiresAt,
//                entity::setDeviceCodeMetadata
//        );

        return entity;
    }

    /**
     * 발급한 토큰에 관한 정보를 처리하는 메소드
     * @param token
     * @param tokenValueConsumer
     * @param issuedAtConsumer
     * @param expiresAtConsumer
     * @param metadataConsumer
     */
    private void setTokenValues(
            OAuth2Authorization.Token<?> token,  // OAuth2 인가 서버에서 발급한 토큰
            Consumer<String> tokenValueConsumer, // 토큰의 값
            Consumer<Instant> issuedAtConsumer,  // 토큰 발행 시간
            Consumer<Instant> expiresAtConsumer, // 토큰 만료 시간
            Consumer<String> metadataConsumer) { // 토큰의 메타데이터

        // 필요한 consumer에게 정보를 넘김
        if (token != null) {
            OAuth2Token oAuth2Token = token.getToken();
            tokenValueConsumer.accept(oAuth2Token.getTokenValue());
            issuedAtConsumer.accept(oAuth2Token.getIssuedAt());
            expiresAtConsumer.accept(oAuth2Token.getExpiresAt());
            metadataConsumer.accept(writeMap(token.getMetadata()));
        }
    }

    /**
     * JSON 형식의 문자열을 Map 형식으로 변환하는 메소드
     * @param data
     * @return Map&lt;String, Object&gt;
     */
    private Map<String, Object> parseMap(String data) {
        try {
            return this.objectMapper.readValue(data, new TypeReference<Map<String, Object>>() {
            });
        } catch (Exception ex) {
            throw new IllegalArgumentException(ex.getMessage(), ex);
        }
    }

    /**
     * Map 형식을 JSON 형식으로 직렬화하는 메소드
     * @param metadata
     * @return String
     */
    private String writeMap(Map<String, Object> metadata) {
        try {
            return this.objectMapper.writeValueAsString(metadata);
        } catch (Exception ex) {
            throw new IllegalArgumentException(ex.getMessage(), ex);
        }
    }

    /**
     * 문자열 형태인 AuthorizationGrantType을 AuthorizationGrantType 열거형 형태로 변환하는 메소드
     * @param authorizationGrantType
     * @return AuthorizationGrantType
     */
    private static AuthorizationGrantType resolveAuthorizationGrantType(String authorizationGrantType) {
        if (AuthorizationGrantType.AUTHORIZATION_CODE.getValue().equals(authorizationGrantType)) {
            return AuthorizationGrantType.AUTHORIZATION_CODE;
        } else if (AuthorizationGrantType.CLIENT_CREDENTIALS.getValue().equals(authorizationGrantType)) {
            return AuthorizationGrantType.CLIENT_CREDENTIALS;
        } else if (AuthorizationGrantType.REFRESH_TOKEN.getValue().equals(authorizationGrantType)) {
            return AuthorizationGrantType.REFRESH_TOKEN;
        } else if (AuthorizationGrantType.DEVICE_CODE.getValue().equals(authorizationGrantType)) {
            return AuthorizationGrantType.DEVICE_CODE;
        }
        return new AuthorizationGrantType(authorizationGrantType);
    }
}

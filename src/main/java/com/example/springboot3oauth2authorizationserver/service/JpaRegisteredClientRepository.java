package com.example.springboot3oauth2authorizationserver.service;

import com.example.springboot3oauth2authorizationserver.repository.ClientRepository;
import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.type.TypeReference;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.example.springboot3oauth2authorizationserver.entity.Client;

/**
 * OAuth2 서버에서 클라이언트의 등록된 정보를 검색하고 제공<br>
 * RegisteredClient는 Spring Security에서 OAuth 2.0 및 OpenID Connect 클라이언트를 나타내는 모델 클래스
 * @implement : RegisteredClientRepository
 */
@Component
public class JpaRegisteredClientRepository implements RegisteredClientRepository {


    private final ClientRepository clientRepository;

    // Jzckson 라이브러리를 사용하여 JSON 데이터를 객체로 변환할 때 사용
    private final ObjectMapper objectMapper = new ObjectMapper();

    public JpaRegisteredClientRepository(ClientRepository clientRepository) {
        Assert.notNull(clientRepository, "clientRepository cannot be null");
        this.clientRepository = clientRepository;

        // Spring security에서 사용하는 JSON 직렬화 및 역직렬화 모듈을 가져와서 주입
        ClassLoader classLoader = JpaRegisteredClientRepository.class.getClassLoader();
        List<Module> securityModules = SecurityJackson2Modules.getModules(classLoader);
        this.objectMapper.registerModules(securityModules);

        // Oauth2AuthorizationServerJackson2Module OAuth2 관련 객체들을 Jackson이 올바르게 처리할 수 있도록 하는 모듈
        this.objectMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
    }

    /**
     * RegisteredClient를 Client Entity로 변환하여 DB에 저장하는 메소드
     * @param registeredClient the {@link RegisteredClient}
     */
    @Override
    public void save(RegisteredClient registeredClient) {
        Assert.notNull(registeredClient, "registeredClient cannot be null");
        this.clientRepository.save(toEntity(registeredClient));
    }

    /**
     * Client를 DB에서 ID로 조회하고, RegisteredClient 객체로 변환해서 전달하는 메소드
     * @param id the registration identifier
     * @return RegisteredClient
     */
    @Override
    public RegisteredClient findById(String id) {
        Assert.hasText(id, "id cannot be empty");
        return this.clientRepository.findById(id).map(this::toObject).orElse(null);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        return null;
    }

    /**
     * Client를 RegisteredClient 객체로 변환하는 메소드
     * @param Client
     * @return RegisteredClient
     */
    private RegisteredClient toObject(Client client) {
        // Client 객체의 clientAuthenticationMethods 필드를 콤마(,)로 구분된 문자열로 Set으로 변환함
        // 클라이언트의 인증 방법을 나타냄
        Set<String> clientAuthenticationMethods =
                StringUtils.commaDelimitedListToSet(client.getClientAuthenticationMethods());

        // Client 객체의 authorizationGrantType 필드를 콤마(,)로 구분된 문자열에서 Set으로 변환함
        // 클라이언트의 권한 부여 유형을 나타냄
        Set<String> authorizationGrantTypes =
                StringUtils.commaDelimitedListToSet(client.getAuthorizationGrantTypes());

        // Client 객체의 redirectUris 필드를 콤마(,)로 구분된 문자열에서 Set으로 변환함
        // 리다이렉트 URI -> authorization_code, Access Token이 전달될 경로를 의미함
        Set<String> redirectUris =
                StringUtils.commaDelimitedListToSet(client.getRedirectUris());

        // Client 객체의 postLogoutRedirectUris 필드를 콤마(,)로 구분된 문자열에서 Set으로 변환함
        // 로그아웃 후에 리다이렉트될 URI를 의미함
        Set<String> postLogoutRedirectUris =
                StringUtils.commaDelimitedListToSet(client.getPostLogoutRedirectUris());

        // Client 객체의 clientScopes 필드를 콤마(,)로 구분된 문자열에서 Set으로 변환함
        // // 클라이언트가 요청할 수 있는 정보에 대한 권한(아이디, 프로필, 이메일 등)
        Set<String> clientScopes =
                StringUtils.commaDelimitedListToSet(client.getScopes());

        // RegisteredClient 객체를 builder 패턴을 사용햐서 Client Entity의 정보를 옮김
        RegisteredClient.Builder builder = RegisteredClient.withId(client.getId())
                .clientId(client.getClientId())
                .clientIdIssuedAt(client.getClientIdIssuedAt())
                .clientSecret(client.getClientSecret())
                .clientSecretExpiresAt(client.getClientSecretExpiresAt())
                .clientName(client.getClientName())

                // 문자열 형태를 ClientAuthenticationMethod의 열거형 형태로 변환해서 저장
                .clientAuthenticationMethods(authenticationMethods ->
                        clientAuthenticationMethods.forEach(authenticationMethod ->
                                authenticationMethods.add(resolveClientAuthenticationMethod(authenticationMethod))))

                // 문자열 형태를 AuthorizationGrantType의 열거형 형태로 변환해서 저장
                .authorizationGrantTypes((grantTypes) ->
                        authorizationGrantTypes.forEach(grantType ->
                                grantTypes.add(resolveAuthorizationGrantType(grantType))))

                .redirectUris((uris) -> uris.addAll(redirectUris))
                .postLogoutRedirectUris((uris) -> uris.addAll(postLogoutRedirectUris))
                .scopes((scopes) -> scopes.addAll(clientScopes));

        // null이 아닐 경우에만 변환하도록 if문 사용
        if(client.getClientSettings() != null) {
            Map<String, Object> clientSettingsMap = parseMap(client.getClientSettings());
            builder.clientSettings(ClientSettings.withSettings(clientSettingsMap).build());
        }

        // null이 아닐 경우에만 변환하도록 if문 사용
        if(client.getTokenSettings() != null) {
            Map<String, Object> tokenSettingsMap = parseMap(client.getTokenSettings());
            builder.tokenSettings(TokenSettings.withSettings(tokenSettingsMap).build());
        }

        return builder.build();
    }

    /**
     * RegisteredClient 객체를 DB에 저장하기 위해 Client Entity로 변환하는 메소드
     * @param registeredClient
     * @return
     */
    private Client toEntity(RegisteredClient registeredClient) {
        // RegisteredClient에서 client가 사용하는 인증 방법을 List로 옮김
        // client_secret_basic : HTTP 헤더에 기본 인증 형식으로 전송 ex) Authorization: Basic base64(client_id:client_secret)
        // client_secret_post : HTTP post 본문에 인코딩하여 전송 ex) client_id=your_client_id&client_secret=your_client_secret
        // private_key_jwt : 클라이언트가 서명된 JWT를 사용하여 자신의 신원을 증명
        // none : 클라이언트 인증하지 않음
        List<String> clientAuthenticationMethods = new ArrayList<>(registeredClient.getClientAuthenticationMethods().size());
        registeredClient.getClientAuthenticationMethods()
                .forEach(clientAuthenticationMethod ->
                clientAuthenticationMethods.add(clientAuthenticationMethod.getValue()));

        // RegisteredClient에서 client의 승인 그랜트 타입을 List로 옮긴다
        // 승인 그랜트 타입(Authorization Code, Client Credentials 등)
        List<String> authorizationGrantTypes = new ArrayList<>(registeredClient.getAuthorizationGrantTypes().size());
        registeredClient.getAuthorizationGrantTypes().forEach(authorizationGrantType ->
                authorizationGrantTypes.add(authorizationGrantType.getValue()));

        // 클라이언트 객체 생성 -> RegisteredClient 정보를 옮김
        Client entity = new Client();
        entity.setId(registeredClient.getId());
        entity.setClientId(registeredClient.getClientId());
        entity.setClientIdIssuedAt(registeredClient.getClientIdIssuedAt());
        entity.setClientSecret(registeredClient.getClientSecret());
        entity.setClientSecretExpiresAt(registeredClient.getClientSecretExpiresAt());
        entity.setClientName(registeredClient.getClientName());
        entity.setClientAuthenticationMethods(StringUtils.collectionToCommaDelimitedString(clientAuthenticationMethods));
        entity.setAuthorizationGrantTypes(StringUtils.collectionToCommaDelimitedString(authorizationGrantTypes));
        entity.setRedirectUris(StringUtils.collectionToCommaDelimitedString(registeredClient.getRedirectUris()));
        entity.setPostLogoutRedirectUris(StringUtils.collectionToCommaDelimitedString(registeredClient.getPostLogoutRedirectUris()));
        entity.setScopes(StringUtils.collectionToCommaDelimitedString(registeredClient.getScopes()));
        entity.setClientSettings(writeMap(registeredClient.getClientSettings().getSettings()));
        entity.setTokenSettings(writeMap(registeredClient.getTokenSettings().getSettings()));

        return entity;
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
     * @param data
     * @return String
     */
    private String writeMap(Map<String, Object> data) {
        try {
            // 주어진 객체를 JSON 형식의 문자열로 직렬화함
            return this.objectMapper.writeValueAsString(data);
        } catch (Exception ex) {
            throw new IllegalArgumentException(ex.getMessage(), ex);
        }
    }

    /**
     * 문자열 형태인 AuthorizationGrantType을 AuthorizationGrantType 열거형 형태로 변환하는 메소드
     * @param authorizationGrantType
     * @return
     */
    private static AuthorizationGrantType resolveAuthorizationGrantType(String authorizationGrantType) {
        if (AuthorizationGrantType.AUTHORIZATION_CODE.getValue().equals(authorizationGrantType)) {
            return AuthorizationGrantType.AUTHORIZATION_CODE;
        } else if (AuthorizationGrantType.CLIENT_CREDENTIALS.getValue().equals(authorizationGrantType)) {
            return AuthorizationGrantType.CLIENT_CREDENTIALS;
            // Bearer Token 타입은 어떻게 하지?
//        } else if (AuthorizationGrantType.JWT_BEARER.getValue().equals(authorizationGrantType)) {
//            return AuthorizationGrantType.JWT_BEARER;
        } else if (AuthorizationGrantType.REFRESH_TOKEN.getValue().equals(authorizationGrantType)) {
            return AuthorizationGrantType.REFRESH_TOKEN;
        }
        // 일치하는 경우가 없을 경우 주어진 문자열을 사용하여 반환함
        return new AuthorizationGrantType(authorizationGrantType);
    }

    /**
     * 문자열 형태인 ClientAuthenticationMethod를 ClientAuthenticationMethod 열거형으로 변환하는 메소드
     * @param clientAuthenticationMethod
     * @return
     */
    private static ClientAuthenticationMethod resolveClientAuthenticationMethod(String clientAuthenticationMethod) {
        if (ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue().equals(clientAuthenticationMethod)) {
            return ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
        } else if (ClientAuthenticationMethod.CLIENT_SECRET_POST.getValue().equals(clientAuthenticationMethod)) {
            return ClientAuthenticationMethod.CLIENT_SECRET_POST;
        } else if (ClientAuthenticationMethod.NONE.getValue().equals(clientAuthenticationMethod)) {
            return ClientAuthenticationMethod.NONE;
        }
        // 일치하는 경우가 없을 경우, 주어진 문자열을 사용하여 반환함
        return new ClientAuthenticationMethod(clientAuthenticationMethod);
    }


}

package com.example.springboot3oauth2authorizationserver.config;

import com.example.springboot3oauth2authorizationserver.entity.Client;
import com.example.springboot3oauth2authorizationserver.entity.Role;
import com.example.springboot3oauth2authorizationserver.entity.User;
import com.example.springboot3oauth2authorizationserver.repository.ClientRepository;
import com.example.springboot3oauth2authorizationserver.repository.RoleRepository;
import com.example.springboot3oauth2authorizationserver.repository.UserRepository;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 *
 * @author gopang
 */

@Component
public class DatabaseLoader {

    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final ClientRepository clientRepository;

    public DatabaseLoader(PasswordEncoder passwordEncoder, UserRepository userRepository, RoleRepository roleRepository, ClientRepository clientRepository) {
        this.passwordEncoder = passwordEncoder;
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.clientRepository = clientRepository;
    }

    //초기화 하는 메서드
    @PostConstruct
    void init(){
        clientCreation();
        roleCreation();
    }

    private void clientCreation() {
        // 클라이언트가 이미 존재하는지 확인
        Optional<Client> clientOptional = clientRepository.findByClientId("demo-client");
        if(clientOptional.isPresent()) return;

        // 클라이언트의 인증 방법 설정
        List<String> clientAuthenticationMethods = new ArrayList<>();
        clientAuthenticationMethods.add(ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue());
        clientAuthenticationMethods.add(ClientAuthenticationMethod.CLIENT_SECRET_POST.getValue());

        // 클라이언트의 권한 부여 타입 설정
        List<String> authorizationGrantTypes = new ArrayList<>();
        authorizationGrantTypes.add(AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
        authorizationGrantTypes.add(AuthorizationGrantType.REFRESH_TOKEN.getValue());
        authorizationGrantTypes.add(AuthorizationGrantType.CLIENT_CREDENTIALS.getValue());

        // 클라이언트의 리다이렉트 URI 설정
        List<String> redirectUri = new ArrayList<>();
        redirectUri.add("https://oidcdebugger.com/debug");
        redirectUri.add("http://127.0.0.1:9191/login/oauth2/code/demo-client-oidc");
        redirectUri.add("http://127.0.0.1:9191/authorized");

        // 클라이언트의 스코프 설정
        List<String> scope = new ArrayList<>();
        scope.add(OidcScopes.OPENID);
        scope.add("demo.read");
        scope.add("demo.write");

        // 클라이언트 객체 생성 및 속성 설정
        Client client = new Client();
        client.setId(UUID.randomUUID().toString());
        client.setClientId("demo-client");
        client.setClientSecret(passwordEncoder.encode("demo-client-secret"));
        client.setClientAuthenticationMethods(StringUtils.collectionToCommaDelimitedString(clientAuthenticationMethods));
        client.setAuthorizationGrantTypes(StringUtils.collectionToCommaDelimitedString(authorizationGrantTypes));
        client.setRedirectUris(StringUtils.collectionToCommaDelimitedString(redirectUri));
        client.setScopes(StringUtils.collectionToCommaDelimitedString(scope));
        client.setClientSettings(null);
        client.setTokenSettings(null);

        // 데이터베이스에 클라이언트 저장
        clientRepository.save(client);

    }

    // 새로생성된 유저에게 "ROLE_USER" 권한 부여
    private void roleCreation() {
        Optional<Role> roleOptional = roleRepository.findByName("ROLE_USER");
        if(roleOptional.isPresent()) return;
        Role role = roleRepository.save(new Role("ROLE_USER"));
        createUser("user", role);
    }

    // 유저 회원가입
    private void createUser(String email, Role role) {
        Optional<User> userOptional = userRepository.findByEmail(email);
        if(userOptional.isPresent()) return;
        User user = new User();
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode("password"));
        user.setRole(role);
        user.setActive(Boolean.TRUE);
        userRepository.save(user);

    }
}

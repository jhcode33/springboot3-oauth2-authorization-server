package com.example.springboot3oauth2authorizationserver.config;

import com.example.springboot3oauth2authorizationserver.jose.Jwks;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

/**
 *
 * @author gopang
 */
@Configuration(proxyBeanMethods = false)
@RequiredArgsConstructor
public class AuthorizationServerConfig {

    private final JWKSource<SecurityContext> jwkSource;
    private final JwtDecoder jwtDecoder;

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE) //가장 높은 우선순위 값을 가짐
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception{

        // OAuth2 AuthorizationServer의 기본 구성을 사용함
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                // OpenId Connection 활성화
                .oidc(Customizer.withDefaults()); // Enable OpenId Connection 1.0

        // userinfo 구성
        http.oauth2ResourceServer((oauth2ResourceServer) ->
                oauth2ResourceServer
                        .jwt((jwt) ->
                                jwt.decoder(jwtDecoder)
                        )
        );

        // 예외 처리 구성
        http.exceptionHandling(exceptions -> exceptions
                .defaultAuthenticationEntryPointFor(
                        // 미인증 진입점 (no authentication_code, no token)
                        new LoginUrlAuthenticationEntryPoint("/login"),
                        new MediaTypeRequestMatcher(MediaType.TEXT_HTML))
        );
        return http.build();
    }

    //토큰 발급자(issuer)설정, 발급한 인가 서버를 식별하는데 사용.
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().issuer("http://localhost:9090").build();
    }

    // 패스워드 암호화 BCryptPasswordEncoder 괄호안의 숫자가 높을 수록 라운드 수가 많아져서 보안강화
    // 너무 높게 잡으면 계산비용이 높게 발생됨
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(4);
    }



}

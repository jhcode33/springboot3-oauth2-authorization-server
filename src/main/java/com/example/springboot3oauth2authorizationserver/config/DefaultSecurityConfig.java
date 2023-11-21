package com.example.springboot3oauth2authorizationserver.config;

import com.example.springboot3oauth2authorizationserver.handler.CustomAccessDeniedHandler;
import com.example.springboot3oauth2authorizationserver.security.JpaUserDetailsManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.net.URI;
import java.util.Arrays;
import java.util.List;

/**
 *
 * @author gopang
 */

@EnableWebSecurity
@Configuration
public class DefaultSecurityConfig {

    private final PasswordEncoder passwordEncoder;
    private final JpaUserDetailsManager jpaUserDetailsManager;
  /*  private final ClientRegistrationRepository clientRegistrationRepository;*/

    public DefaultSecurityConfig(PasswordEncoder passwordEncoder, JpaUserDetailsManager jpaUserDetailsManager/*, ClientRegistrationRepository clientRegistrationRepository*/) {
        this.passwordEncoder = passwordEncoder;
        this.jpaUserDetailsManager = jpaUserDetailsManager;
//        this.clientRegistrationRepository = clientRegistrationRepository;
    }

    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(authorize ->
                        authorize.requestMatchers("/join/**", "/login/**").permitAll()
                                .anyRequest().permitAll())
                // 모든 요청에 대해서 인증해야 함

                // security에서 제공하는 기본 login 페이지를 활용
                .formLogin(Customizer.withDefaults());
//                .logout(logout -> logout
//                        .logoutSuccessHandler(oidcLogoutSuccessHandler()));

        return http.build();

    }

    // 사용자 인증, 비밀번혹 검증, 계정잠금여부 확인하여 조치, 권한부여까지 함
    @Bean
    public DaoAuthenticationProvider jpaDaoAuthenticationProvider() {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setUserDetailsService(jpaUserDetailsManager);
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder);
        return daoAuthenticationProvider;
    }

    /* CORS */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of("*"));
        configuration.setAllowedMethods(Arrays.asList("GET","POST", "OPTIONS", "PATCH", "DELETE"));
        configuration.setAllowedHeaders(Arrays.asList("Content-Type", "Authorization"));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }


    /*@Bean
    public LogoutSuccessHandler oidcLogoutSuccessHandler(){
        OidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler  =
                new OidcClientInitiatedLogoutSuccessHandler(
                        this.clientRegistrationRepository);

        oidcLogoutSuccessHandler.setPostLogoutRedirectUri(
                String.valueOf(URI.create("http://localhost:9090/oauth2/revoke")));

        return oidcLogoutSuccessHandler;
    }*/

}

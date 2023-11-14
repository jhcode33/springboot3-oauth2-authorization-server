package com.example.springboot3oauth2authorizationserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

/**
 *
 * @author gopang
 */

@EnableWebSecurity
public class DefaultSecurityConfig {

    private final PasswordEncoder passwordEncoder;
    private final JpaUserDetailsManager jpaUserDetailsManager;

    public DefaultSecurityConfig(PasswordEncoder passwordEncoder, JpaUserDetailsManager jpaUserDetailsManager) {
        this.passwordEncoder = passwordEncoder;
        this.jpaUserDetailsManager = jpaUserDetailsManager;
    }

    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                // 모든 요청에 대해서 인증해야 함
                .authorizeHttpRequests(authorize -> authorize
                        .anyRequest().authenticated()
                )
                // security에서 제공하는 기본 login 페이지를 활용
                .formLogin(Customizer.withDefaults());
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

}

package com.example.springboot3oauth2authorizationserver.security;

import com.example.springboot3oauth2authorizationserver.entity.Role;
import com.example.springboot3oauth2authorizationserver.entity.User;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Spring Security 사용자의 인증 정보를 제공
 * @implements UserDetails
 */
@JsonDeserialize(using = CustomUserPrincipalDeserializer.class)
public class CustomUserPrincipal implements UserDetails {

    private Long id;

    private String username;

    private String password;

    private Role role;

    private boolean enable;

    private List<GrantedAuthority> authorities = new ArrayList<>();

    public CustomUserPrincipal() {
        super();
    }

    public CustomUserPrincipal(Long id, String username, String password, boolean enable, List<GrantedAuthority> authorities) {
        this.id = id;
        this.username = username;
        this.password = password;
        this.enable = enable;
        this.authorities = authorities;
    }

    public CustomUserPrincipal(Long id, String username, String password, Role role, boolean enable) {
        this.id = id;
        this.username = username;
        this.password = password;
        this.role = role;
        this.enable = enable;
    }

    public CustomUserPrincipal(Long id, String username, String password, Role role, boolean enable, List<GrantedAuthority> authorities) {
        this.id = id;
        this.username = username;
        this.password = password;
        this.role = role;
        this.enable = enable;
        this.authorities = authorities;

    }

    public static CustomUserPrincipal create(User user){
        return new CustomUserPrincipal(
                user.getId(),
                user.getUsername(),
                user.getPassword(),
                user.getRole(),
                user.getActive()
        );
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return AuthorityUtils.createAuthorityList(this.role.getName());
    }

    @Override
    public boolean isAccountNonExpired() {
        return enable;
    }

    @Override
    public boolean isAccountNonLocked() {
        return enable;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return enable;
    }

    @Override
    public boolean isEnabled() {
        return enable;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    public Long getId() {
        return id;
    }
}

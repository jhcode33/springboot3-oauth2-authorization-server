package com.example.springboot3oauth2authorizationserver.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import lombok.Data;

import java.io.Serializable;
import java.util.Objects;

@Entity
@Data
// AuthorizationConsentId 클래스의 Key를 복합 주키로 사용하겠다고 선언
@IdClass(AuthorizationConsent.AuthorizationConsentId.class)
public class AuthorizationConsent implements Serializable {

    // Client Id
    @Id
    private String registeredClientId;

    // Client에게 권한을 위임한 사용자(Principal)의 이름
    @Id
    private String principalName;

    // Client에게 사용자가 위임한 권한의 목록
    @Column(length = 1000)
    private String authorities;

    public static class AuthorizationConsentId implements Serializable {
        private String registeredClientId;
        private String principalName;

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            AuthorizationConsentId that = (AuthorizationConsentId) o;
            return registeredClientId.equals(that.registeredClientId) && principalName.equals(that.principalName);
        }

        @Override
        public int hashCode() {
            return Objects.hash(registeredClientId, principalName);
        }
    }

}

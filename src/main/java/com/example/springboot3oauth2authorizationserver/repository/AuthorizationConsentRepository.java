package com.example.springboot3oauth2authorizationserver.repository;

import com.example.springboot3oauth2authorizationserver.entity.AuthorizationConsent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface AuthorizationConsentRepository extends JpaRepository<AuthorizationConsent, AuthorizationConsent.AuthorizationConsentId> {

    /**
     * 권한을 위임한 사용자와 위임 받은 Client 찾기
     * @param registeredClientId
     * @param principalName
     * @return
     */
    Optional<AuthorizationConsent> findByRegisteredClientIdAndPrincipalName(String registeredClientId, String principalName);

    /**
     * 위임한 권한 삭제
     * @param registeredClientId
     * @param principalName
     */
    void deleteByRegisteredClientIdAndPrincipalName(String registeredClientId, String principalName);
}

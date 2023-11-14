package com.example.springboot3oauth2authorizationserver.repository;

import com.example.springboot3oauth2authorizationserver.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    /**
     * 사용자를 email(username)으로 찾는다
     * @param email
     * @return Optional&lt;User&gt;
     */
    Optional<User> findByEmail(String email);
}

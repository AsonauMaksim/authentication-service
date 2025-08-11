package com.internship.authentication_service.repository;

import com.internship.authentication_service.entity.RefreshToken;
import com.internship.authentication_service.entity.UserCredentials;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    Optional<RefreshToken> findByToken(String token);

    void deleteByToken(String token);

    void deleteByUser(UserCredentials user);
}

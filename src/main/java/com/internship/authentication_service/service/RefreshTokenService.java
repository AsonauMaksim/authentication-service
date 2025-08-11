package com.internship.authentication_service.service;

import com.internship.authentication_service.entity.RefreshToken;
import com.internship.authentication_service.entity.UserCredentials;

import java.util.Optional;

public interface RefreshTokenService {

    RefreshToken createRefreshToken(UserCredentials user);

    RefreshToken validateRefreshToken(String token);

    void deleteRefreshToken(String token);

    Optional<RefreshToken> findByToken(String token);
}

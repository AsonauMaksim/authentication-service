package com.internship.authentication_service.service;

import com.internship.authentication_service.dto.AuthRequest;
import com.internship.authentication_service.dto.TokenResponse;

public interface AuthService {

    TokenResponse register(AuthRequest request);
    TokenResponse login(AuthRequest request);
    TokenResponse refreshToken(String refreshToken);
    String logout(String refreshToken);
    void deleteByUsername(String username);
}

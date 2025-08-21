package com.internship.authentication_service.service.impl;

import com.internship.authentication_service.dto.AuthRequest;
import com.internship.authentication_service.dto.TokenResponse;
import com.internship.authentication_service.entity.RefreshToken;
import com.internship.authentication_service.entity.UserCredentials;
import com.internship.authentication_service.exception.AlreadyExistsException;
import com.internship.authentication_service.exception.InvalidTokenException;
import com.internship.authentication_service.exception.UnauthorizedException;
import com.internship.authentication_service.repository.UserCredentialsRepository;
import com.internship.authentication_service.service.AuthService;
import com.internship.authentication_service.service.JwtService;
import com.internship.authentication_service.service.RefreshTokenService;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthServiceImpl.class);

    private final UserCredentialsRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;


    @Override
    public TokenResponse register(AuthRequest request) {

        String username = request.getUsername();
        log.debug("Attempting registration for username '{}'", username);

        if (repository.existsByUsername(username)) {
            log.warn("Registration failed: username '{}' already exists", username);
            throw new AlreadyExistsException("User with username '" + username + "' already exists");
        }

        UserCredentials user = UserCredentials.builder()
                .username(username)
                .password(passwordEncoder.encode(request.getPassword()))
                .build();

        repository.save(user);
        log.info("User '{}' registered successfully", username);

        String accessToken = jwtService.generateAccessToken(user.getId());
        String refreshToken = refreshTokenService.createRefreshToken(user).getToken();

        return new TokenResponse(accessToken, refreshToken);
    }

    @Override
    public TokenResponse login(AuthRequest request) {

        String username = request.getUsername();
        log.debug("Attempting login for username '{}'", username);

        UserCredentials user = repository.findByUsername(username)
                .orElseThrow(() -> {
                    log.warn("Login failed: username '{}' not found", username);
                    return new UnauthorizedException("Invalid credentials");
                });

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            log.warn("Login failed: incorrect password for username '{}'", username);
            throw new UnauthorizedException("Invalid credentials");
        }

        log.info("User '{}' authenticated successfully", username);

        String accessToken = jwtService.generateAccessToken(user.getId());
        String refreshToken = refreshTokenService.createRefreshToken(user).getToken();

        return new TokenResponse(accessToken, refreshToken);
    }

    @Override
    public TokenResponse refreshToken(String refreshToken) {

        log.debug("Attempting to refresh access token using refresh token: {}", refreshToken);

        RefreshToken token = refreshTokenService.validateRefreshToken(refreshToken);
        UserCredentials user = token.getUser();

        refreshTokenService.deleteRefreshToken(refreshToken);
        log.info("Refresh token used and deleted for user '{}'", user.getUsername());

        String accessToken = jwtService.generateAccessToken(user.getId());
        String newRefreshToken = refreshTokenService.createRefreshToken(user).getToken();

        return new TokenResponse(accessToken, newRefreshToken);
    }

    @Override
    public String logout(String refreshToken) {
        log.debug("Logging out using refresh token: {}", refreshToken);

        refreshTokenService.findByToken(refreshToken)
                .orElseThrow(() -> new InvalidTokenException("Refresh token not found"));

        refreshTokenService.deleteRefreshToken(refreshToken);
        log.info("Refresh token invalidated successfully");

        return "Refresh token successfully invalidated";
    }
}

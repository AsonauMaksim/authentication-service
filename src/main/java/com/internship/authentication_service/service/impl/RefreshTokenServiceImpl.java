package com.internship.authentication_service.service.impl;

import com.internship.authentication_service.config.JwtProperties;
import com.internship.authentication_service.entity.RefreshToken;
import com.internship.authentication_service.entity.UserCredentials;
import com.internship.authentication_service.exception.InvalidTokenException;
import com.internship.authentication_service.repository.RefreshTokenRepository;
import com.internship.authentication_service.service.RefreshTokenService;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;


import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenServiceImpl implements RefreshTokenService {

    private static final Logger log = LoggerFactory.getLogger(RefreshTokenServiceImpl.class);

    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtProperties jwtProperties;

    @Override
    @Transactional
    public RefreshToken createRefreshToken(UserCredentials user) {

        log.debug("Creating new refresh token for user '{}'", user.getUsername());

        refreshTokenRepository.deleteByUser(user);
        log.debug("Deleted existing refresh tokens for user '{}'", user.getUsername());

        String token = UUID.randomUUID().toString();
        Instant now = Instant.now();
        Instant expiry = now.plusMillis(jwtProperties.getRefreshTokenExpirationMs());

        RefreshToken refreshToken = RefreshToken.builder()
                .user(user)
                .token(token)
                .expiryDate(expiry)
                .build();

        RefreshToken saved = refreshTokenRepository.save(refreshToken);
        log.debug("Saved new refresh token: {}", saved.getToken());

        return saved;
    }

    @Override
    public RefreshToken validateRefreshToken(String token) {
        log.debug("Validating refresh token: {}", token);

        RefreshToken refreshToken = refreshTokenRepository.findByToken(token)
                .orElseThrow(() -> {
                    log.warn("Refresh token not found: {}", token);
                    return new InvalidTokenException("Invalid refresh token");
                });

        Instant now = Instant.now();
        if (refreshToken.getExpiryDate().isBefore(now)) {
            refreshTokenRepository.delete(refreshToken);
            log.warn("Refresh token expired and deleted: {}", token);
            throw new InvalidTokenException("Refresh token expired");
        }

        log.debug("Refresh token is valid for user '{}'", refreshToken.getUser().getUsername());
        return refreshToken;
    }

    @Override
    @Transactional
    public void deleteRefreshToken(String token) {

        refreshTokenRepository.deleteByToken(token);
        log.debug("Deleted refresh token: {}", token);
    }

    @Override
    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }
}

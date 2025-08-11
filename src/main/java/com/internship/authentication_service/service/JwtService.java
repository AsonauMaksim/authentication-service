package com.internship.authentication_service.service;

import com.internship.authentication_service.config.JwtProperties;
import com.internship.authentication_service.exception.InvalidTokenException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;

@Service
@RequiredArgsConstructor
public class JwtService {

    private static final Logger log = LoggerFactory.getLogger(JwtService.class);
    private final JwtProperties jwtProperties;
    private SecretKey key;


    @PostConstruct
    public void init() {
        this.key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtProperties.getSecret()));
    }

    public String generateAccessToken(Long userId) {

        log.debug("Generating access token for userId={}", userId);
        return Jwts.builder()
                .subject(userId.toString())
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + jwtProperties.getAccessTokenExpirationMs()))
                .signWith(key)
                .compact();
    }

    public boolean isTokenValid(String token) {

        if (token == null || !token.matches("^[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+$")) {
            log.warn("Invalid token format: {}", token);
            return false;
        }

        try {
            validateTokenOrThrow(token);
            return true;
        } catch (InvalidTokenException e) {
            return false;
        }
    }

    public void validateTokenOrThrow(String token) {

        try {
            Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(token);
        } catch (JwtException e) {
            log.warn("JWT validation failed: {}", e.getMessage());
            throw new InvalidTokenException("Invalid or expired JWT token", e);
        }
    }

    public Long extractUserId(String token) {

        Claims claims = Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();

        Long userId = Long.parseLong(claims.getSubject());
        log.debug("Extracted userId={} from access token", userId);
        return userId;
    }
}

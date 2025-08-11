package com.internship.authentication_service.unit.service;

import com.internship.authentication_service.config.JwtProperties;
import com.internship.authentication_service.exception.InvalidTokenException;
import com.internship.authentication_service.service.JwtService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class JwtServiceTest {

    private JwtService jwtService;

    private static String randomBase64Secret() {
        byte[] buf = new byte[64];
        new SecureRandom().nextBytes(buf);
        return Base64.getEncoder().encodeToString(buf);
    }

    @BeforeEach
    void setUp() {
        JwtProperties props = new JwtProperties();
        props.setSecret(randomBase64Secret());
        props.setAccessTokenExpirationMs(60_000);
        props.setRefreshTokenExpirationMs(86_400_000);

        jwtService = new JwtService(props);
        jwtService.init();
    }

    @Test
    void generateAndValidate_andExtractUserId() {
        Long userId = 42L;

        String token = jwtService.generateAccessToken(userId);
        assertThat(token).isNotBlank();

        assertThat(jwtService.isTokenValid(token)).isTrue();

        Long extracted = jwtService.extractUserId(token);
        assertThat(extracted).isEqualTo(userId);
    }

    @Test
    void validateTokenOrThrow_shouldThrowOnGarbage() {
        String garbage = "abc.def.ghi";
        assertThatThrownBy(() -> jwtService.validateTokenOrThrow(garbage))
                .isInstanceOf(InvalidTokenException.class);
        assertThat(jwtService.isTokenValid(garbage)).isFalse();
    }

    @Test
    void isTokenValid_shouldReturnFalse_forMalformedToken() {
        assertThat(jwtService.isTokenValid("not-a-jwt")).isFalse();
    }

    @Test
    void isTokenValid_shouldReturnFalse_forNullOrEmpty() {
        assertThat(jwtService.isTokenValid(null)).isFalse();
        assertThat(jwtService.isTokenValid("")).isFalse();
    }

    @Test
    void isTokenValid_shouldReturnFalse_forExpiredToken() throws InterruptedException {
        JwtProperties shortProps = new JwtProperties();
        shortProps.setSecret(randomBase64Secret());
        shortProps.setAccessTokenExpirationMs(1);
        shortProps.setRefreshTokenExpirationMs(1000);
        JwtService shortLivedService = new JwtService(shortProps);
        shortLivedService.init();

        String token = shortLivedService.generateAccessToken(123L);
        Thread.sleep(5);
        assertThat(shortLivedService.isTokenValid(token)).isFalse();
    }
}

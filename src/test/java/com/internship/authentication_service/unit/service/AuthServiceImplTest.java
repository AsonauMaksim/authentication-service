package com.internship.authentication_service.unit.service;

import com.internship.authentication_service.config.JwtProperties;
import com.internship.authentication_service.dto.AuthRequest;
import com.internship.authentication_service.dto.TokenResponse;
import com.internship.authentication_service.entity.RefreshToken;
import com.internship.authentication_service.entity.UserCredentials;
import com.internship.authentication_service.exception.AlreadyExistsException;
import com.internship.authentication_service.exception.InvalidTokenException;
import com.internship.authentication_service.exception.UnauthorizedException;
import com.internship.authentication_service.repository.UserCredentialsRepository;
import com.internship.authentication_service.service.JwtService;
import com.internship.authentication_service.service.RefreshTokenService;
import com.internship.authentication_service.service.impl.AuthServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AuthServiceImplTest {

    private UserCredentialsRepository userRepo;
    private PasswordEncoder passwordEncoder;
    private RefreshTokenService refreshTokenService;
    private JwtService jwtService;

    private AuthServiceImpl authService;

    private static String randomBase64Secret() {
        byte[] buf = new byte[64];
        new SecureRandom().nextBytes(buf);
        return Base64.getEncoder().encodeToString(buf);
    }

    @BeforeEach
    void setUp() {
        userRepo = mock(UserCredentialsRepository.class);
        passwordEncoder = mock(PasswordEncoder.class);
        refreshTokenService = mock(RefreshTokenService.class);

        JwtProperties props = new JwtProperties();
        props.setSecret(randomBase64Secret());
        props.setAccessTokenExpirationMs(60_000);
        props.setRefreshTokenExpirationMs(86_400_000);

        jwtService = new JwtService(props);
        jwtService.init();

        authService = new AuthServiceImpl(userRepo, passwordEncoder, jwtService, refreshTokenService);
    }

    @Test
    void register_success() {
        AuthRequest req = new AuthRequest();
        req.setUsername("alex");
        req.setPassword("verysecurepwd");

        when(userRepo.existsByUsername("alex")).thenReturn(false);
        when(passwordEncoder.encode("verysecurepwd")).thenReturn("ENC");
        // эмулируем сохранение и присвоение id
        when(userRepo.save(any())).thenAnswer(inv -> {
            UserCredentials uc = inv.getArgument(0);
            uc.setId(1L);
            return uc;
        });

        when(refreshTokenService.createRefreshToken(any()))
                .thenReturn(RefreshToken.builder().token("REFRESH-1").build());

        TokenResponse resp = authService.register(req);
        assertThat(resp.getAccessToken()).isNotBlank();
        assertThat(resp.getRefreshToken()).isEqualTo("REFRESH-1");

        ArgumentCaptor<UserCredentials> cap = ArgumentCaptor.forClass(UserCredentials.class);
        verify(userRepo).save(cap.capture());
        assertThat(cap.getValue().getUsername()).isEqualTo("alex");
        assertThat(cap.getValue().getPassword()).isEqualTo("ENC");
    }

    @Test
    void register_conflict() {
        AuthRequest req = new AuthRequest();
        req.setUsername("alex");
        req.setPassword("pwd");

        when(userRepo.existsByUsername("alex")).thenReturn(true);

        assertThatThrownBy(() -> authService.register(req))
                .isInstanceOf(AlreadyExistsException.class);
    }

    @Test
    void login_success() {
        AuthRequest req = new AuthRequest();
        req.setUsername("bob");
        req.setPassword("secret");

        UserCredentials user = UserCredentials.builder()
                .id(7L).username("bob").password("HASH").build();

        when(userRepo.findByUsername("bob")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("secret", "HASH")).thenReturn(true);
        when(refreshTokenService.createRefreshToken(user))
                .thenReturn(RefreshToken.builder().token("REFRESH-2").build());

        TokenResponse resp = authService.login(req);
        assertThat(resp.getAccessToken()).isNotBlank();
        assertThat(resp.getRefreshToken()).isEqualTo("REFRESH-2");
    }

    @Test
    void login_userNotFound_orBadPassword() {
        AuthRequest req = new AuthRequest();
        req.setUsername("ghost");
        req.setPassword("x");

        when(userRepo.findByUsername("ghost")).thenReturn(Optional.empty());
        assertThatThrownBy(() -> authService.login(req))
                .isInstanceOf(UnauthorizedException.class);

        UserCredentials user = UserCredentials.builder()
                .id(5L).username("ghost").password("HASH").build();
        when(userRepo.findByUsername("ghost")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("x", "HASH")).thenReturn(false);

        assertThatThrownBy(() -> authService.login(req))
                .isInstanceOf(UnauthorizedException.class);
    }

    @Test
    void refreshToken_success() {
        UserCredentials user = UserCredentials.builder()
                .id(11L).username("kate").password("H").build();

        when(refreshTokenService.validateRefreshToken("R1"))
                .thenReturn(RefreshToken.builder().user(user).token("R1").build());
        when(refreshTokenService.createRefreshToken(user))
                .thenReturn(RefreshToken.builder().token("R2").build());

        TokenResponse resp = authService.refreshToken("R1");
        assertThat(resp.getAccessToken()).isNotBlank();
        assertThat(resp.getRefreshToken()).isEqualTo("R2");

        verify(refreshTokenService).deleteRefreshToken("R1");
    }

    @Test
    void refreshToken_invalidToken_shouldThrow() {
        when(refreshTokenService.validateRefreshToken("BAD"))
                .thenThrow(new InvalidTokenException("Invalid refresh token"));

        assertThatThrownBy(() -> authService.refreshToken("BAD"))
                .isInstanceOf(com.internship.authentication_service.exception.InvalidTokenException.class);
    }

    @Test
    void logout_shouldDeleteTokenAndReturnMessage() {
        String token = "R1";

        RefreshToken existingToken = RefreshToken.builder()
                .token(token)
                .user(UserCredentials.builder().id(1L).username("alex").build())
                .build();
        when(refreshTokenService.findByToken(token)).thenReturn(Optional.of(existingToken));

        String result = authService.logout(token);

        verify(refreshTokenService).deleteRefreshToken(token);
        assertThat(result).isEqualTo("Refresh token successfully invalidated");
    }
}
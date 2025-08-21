package com.internship.authentication_service.unit.service;

import com.internship.authentication_service.config.JwtProperties;
import com.internship.authentication_service.entity.RefreshToken;
import com.internship.authentication_service.entity.UserCredentials;
import com.internship.authentication_service.exception.InvalidTokenException;
import com.internship.authentication_service.repository.RefreshTokenRepository;
import com.internship.authentication_service.service.impl.RefreshTokenServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class RefreshTokenServiceImplTest {

    private RefreshTokenRepository repo;
    private RefreshTokenServiceImpl service;

    @BeforeEach
    void setUp() {
        repo = mock(RefreshTokenRepository.class);

        JwtProperties props = new JwtProperties();
        props.setSecret("ignored-here");
        props.setAccessTokenExpirationMs(60_000);
        props.setRefreshTokenExpirationMs(3_600_000);

        service = new RefreshTokenServiceImpl(repo, props);
    }

    @Test
    void createRefreshToken_deletesOldAndSavesNew() {
        UserCredentials user = UserCredentials.builder().id(1L).username("u").build();

        when(repo.save(any(RefreshToken.class))).thenAnswer(inv -> inv.getArgument(0));

        RefreshToken created = service.createRefreshToken(user);

        verify(repo).deleteByUser(user);
        verify(repo).save(any(RefreshToken.class));

        assertThat(created.getUser()).isEqualTo(user);
        assertThat(created.getToken()).isNotBlank();
        assertThat(created.getExpiryDate()).isAfter(Instant.now());
    }

    @Test
    void validateRefreshToken_ok() {
        RefreshToken token = RefreshToken.builder()
                .token("T1")
                .expiryDate(Instant.now().plusSeconds(60))
                .user(UserCredentials.builder().id(1L).username("u").build())
                .build();

        when(repo.findByToken("T1")).thenReturn(Optional.of(token));

        RefreshToken validated = service.validateRefreshToken("T1");
        assertThat(validated).isSameAs(token);
    }

    @Test
    void validateRefreshToken_notFound() {
        when(repo.findByToken("NOPE")).thenReturn(Optional.empty());
        assertThatThrownBy(() -> service.validateRefreshToken("NOPE"))
                .isInstanceOf(InvalidTokenException.class);
    }

    @Test
    void validateRefreshToken_expired_deletesAndThrows() {
        RefreshToken expired = RefreshToken.builder()
                .token("OLD")
                .expiryDate(Instant.now().minusSeconds(5))
                .user(UserCredentials.builder().id(1L).username("u").build())
                .build();

        when(repo.findByToken("OLD")).thenReturn(Optional.of(expired));

        assertThatThrownBy(() -> service.validateRefreshToken("OLD"))
                .isInstanceOf(InvalidTokenException.class);

        verify(repo).delete(expired);
    }

    @Test
    void deleteRefreshToken_callsRepo() {
        service.deleteRefreshToken("T1");
        verify(repo).deleteByToken("T1");
    }

    @Test
    void validateRefreshToken_shouldThrow_whenTokenNotFound() {
        when(repo.findByToken("missing")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.validateRefreshToken("missing"))
                .isInstanceOf(com.internship.authentication_service.exception.InvalidTokenException.class);
    }

    @Test
    void deleteRefreshToken_shouldCallRepo() {
        service.deleteRefreshToken("T1");
        verify(repo).deleteByToken("T1");
    }
}

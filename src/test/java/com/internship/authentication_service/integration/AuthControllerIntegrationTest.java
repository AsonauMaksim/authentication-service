package com.internship.authentication_service.integration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.internship.authentication_service.dto.AuthRequest;
import com.internship.authentication_service.dto.RefreshTokenRequest;
import com.internship.authentication_service.entity.RefreshToken;
import com.internship.authentication_service.entity.UserCredentials;
import com.internship.authentication_service.repository.RefreshTokenRepository;
import com.internship.authentication_service.repository.UserCredentialsRepository;
import com.internship.authentication_service.service.JwtService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class AuthControllerIntegrationTest extends BaseIntegrationTest {

    @Autowired
    MockMvc mockMvc;
    @Autowired
    ObjectMapper objectMapper;
    @Autowired
    UserCredentialsRepository userRepo;
    @Autowired
    RefreshTokenRepository refreshRepo;
    @Autowired
    JwtService jwtService;

    @AfterEach
    void clean() {
        refreshRepo.deleteAll();
        userRepo.deleteAll();
    }

    private AuthRequest authReq(String u, String p) {
        AuthRequest r = new AuthRequest();
        r.setUsername(u);
        r.setPassword(p);
        return r;
    }

    @Test
    void register_ShouldReturn201_AndPersistUser_AndIssueTokens() throws Exception {

        var req = authReq("alex_user", "verystrongpwd");

        var mvcResp = mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isCreated())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.accessToken").isString())
                .andExpect(jsonPath("$.refreshToken").isString())
                .andReturn();

        Optional<UserCredentials> saved = userRepo.findByUsername("alex_user");
        assertThat(saved).isPresent();
        assertThat(saved.get().getPassword()).isNotEqualTo("verystrongpwd");

        String respJson = mvcResp.getResponse().getContentAsString();
        record Tokens(String accessToken, String refreshToken) {}
        Tokens tokens = objectMapper.readValue(respJson, Tokens.class);

        assertThat(jwtService.isTokenValid(tokens.accessToken())).isTrue();
        RefreshToken stored = refreshRepo.findByToken(tokens.refreshToken()).orElseThrow();
        assertThat(stored.getUser().getId()).isEqualTo(saved.get().getId());
    }

    @Test
    void register_ShouldReturn409_WhenUsernameExists() throws Exception {

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(authReq("dupe", "1234567890"))))
                .andExpect(status().isCreated());

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(authReq("dupe", "anotherStrongPwd"))))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.status").value(409))
                .andExpect(jsonPath("$.message").value("User with username 'dupe' already exists"));
    }

    @Test
    void register_ShouldReturn400_OnValidationErrors() throws Exception {

        var bad = authReq("", "short");
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(bad)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Bad Request"))
                .andExpect(jsonPath("$.errors").isArray());
    }

    @Test
    void login_ShouldReturn200_AndNewTokens() throws Exception {

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(authReq("bob", "verystrongpwd"))))
                .andExpect(status().isCreated());

        var mvcResp = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(authReq("bob", "verystrongpwd"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isString())
                .andExpect(jsonPath("$.refreshToken").isString())
                .andReturn();

        record Tokens(String accessToken, String refreshToken) {}
        Tokens tokens = objectMapper.readValue(mvcResp.getResponse().getContentAsString(), Tokens.class);
        assertThat(jwtService.isTokenValid(tokens.accessToken())).isTrue();
        assertThat(refreshRepo.findByToken(tokens.refreshToken())).isPresent();
    }

    @Test
    void login_ShouldReturn401_WhenUserMissingOrBadPassword() throws Exception {

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(authReq("ghost", "whateverpwd"))))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Invalid credentials"));

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(authReq("kate", "verystrongpwd"))))
                .andExpect(status().isCreated());

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(authReq("kate", "wrongpassword"))))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Invalid credentials"));
    }

    @Test
    void refresh_ShouldReturn200_NewTokens_AndInvalidateOldRefresh() throws Exception {

        var reg = mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(authReq("max", "verystrongpwd"))))
                .andExpect(status().isCreated())
                .andReturn();

        record Tokens(String accessToken, String refreshToken) {}
        Tokens initial = objectMapper.readValue(reg.getResponse().getContentAsString(), Tokens.class);

        var refreshReq = new RefreshTokenRequest(initial.refreshToken());
        var refreshResp = mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(refreshReq)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isString())
                .andExpect(jsonPath("$.refreshToken").isString())
                .andReturn();

        Tokens refreshed = objectMapper.readValue(refreshResp.getResponse().getContentAsString(), Tokens.class);

        assertThat(refreshRepo.findByToken(initial.refreshToken())).isEmpty();
        assertThat(refreshRepo.findByToken(refreshed.refreshToken())).isPresent();

        assertThat(jwtService.isTokenValid(refreshed.accessToken())).isTrue();
    }

    @Test
    void refresh_ShouldReturn401_OnInvalidRefreshToken() throws Exception {

        var badReq = new RefreshTokenRequest("does-not-exist");
        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(badReq)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Invalid refresh token"));
    }

    @Test
    void logout_ShouldReturn200_AndDeleteRefreshToken() throws Exception {

        var reg = mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(authReq("logout_user", "verystrongpwd"))))
                .andExpect(status().isCreated())
                .andReturn();

        record Tokens(String accessToken, String refreshToken) {}
        Tokens tokens = objectMapper.readValue(reg.getResponse().getContentAsString(), Tokens.class);
        assertThat(refreshRepo.findByToken(tokens.refreshToken())).isPresent();

        var req = new RefreshTokenRequest(tokens.refreshToken());
        mockMvc.perform(post("/api/auth/logout")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Refresh token successfully invalidated"));

        assertThat(refreshRepo.findByToken(tokens.refreshToken())).isEmpty();
    }

    @Test
    void logout_ShouldReturn401_WhenRefreshTokenNotFound() throws Exception {

        var req = new RefreshTokenRequest("missing");
        mockMvc.perform(post("/api/auth/logout")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Refresh token not found"));
    }

    @Nested
    class JwtFilterSmokeTest {

        /** Тестируем сам JwtAuthFilter на защищённом эндпоинте (ниже добавлен тестовый контроллер) */
        @Test
        void securedEndpoint_ShouldReturn401_WithoutOrWithInvalidToken() throws Exception {

            mockMvc.perform(post("/api/_test/secure-ping"))
                    .andExpect(status().isUnauthorized());

            mockMvc.perform(post("/api/_test/secure-ping")
                            .header("Authorization", "Bearer not-a-jwt"))
                    .andExpect(status().isUnauthorized());
        }

        @Test
        void securedEndpoint_ShouldReturn200_WithValidToken() throws Exception {

            var reg = mockMvc.perform(post("/api/auth/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(authReq("ping", "verystrongpwd"))))
                    .andExpect(status().isCreated())
                    .andReturn();

            record Tokens(String accessToken, String refreshToken) {}
            Tokens tokens = objectMapper.readValue(reg.getResponse().getContentAsString(), Tokens.class);

            mockMvc.perform(post("/api/_test/secure-ping")
                            .header("Authorization", "Bearer " + tokens.accessToken()))
                    .andExpect(status().isOk())
                    .andExpect(content().string("ok"));
        }
    }
}

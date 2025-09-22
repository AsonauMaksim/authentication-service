package com.internship.authentication_service.controller;

import com.internship.authentication_service.dto.AuthRequest;
import com.internship.authentication_service.dto.RefreshTokenRequest;
import com.internship.authentication_service.dto.TokenResponse;
import com.internship.authentication_service.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<TokenResponse> register(@Valid @RequestBody AuthRequest request) {
        TokenResponse response = authService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@Valid @RequestBody AuthRequest request) {
        TokenResponse response = authService.login(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refreshToken(@Valid @RequestBody RefreshTokenRequest request) {
        TokenResponse response = authService.refreshToken(request.getRefreshToken());
        return ResponseEntity.ok(response);
    }

    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(@Valid @RequestBody RefreshTokenRequest request) {
        String message = authService.logout(request.getRefreshToken());

        Map<String, String> response = new HashMap<>();
        response.put("message", message);

        return ResponseEntity.ok(response);
    }

    @DeleteMapping("/delete-by-username")
    public ResponseEntity<Void> deleteByUsername(@RequestParam String username) {

        authService.deleteByUsername(username);
        return ResponseEntity.noContent().build();
    }
}

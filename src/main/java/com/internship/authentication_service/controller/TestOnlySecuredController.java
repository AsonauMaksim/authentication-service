package com.internship.authentication_service.controller;

import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * This controller is used for testing the JWT filter.
 * It is only active when the 'test' profile is enabled.
 */
@RestController
@RequestMapping("/api/_test")
@Profile("test")
public class TestOnlySecuredController {

    /**
     * Secured endpoint for testing.
     * Should only be accessible with a valid JWT token.
     */
    @PostMapping("/secure-ping")
    public ResponseEntity<String> securedPing() {
        return ResponseEntity.ok("ok");
    }
}

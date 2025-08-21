package com.internship.authentication_service.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class AuthRequest {

    @NotBlank(message = "Username must not be blank")
    @Size(max = 50, message = "Username must be at most 50 characters")
    private String username;

    @NotBlank(message = "Password must not be blank")
    @Size(min = 10, max = 255, message = "Password must be between 10 and 255 characters")
    private String password;
}

package com.example.security.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class OAuth2LoginRequest {
    @NotBlank(message = "Le token Google est requis")
    private String googleToken;

    private String deviceInfo;
    private String ipAddress;
}
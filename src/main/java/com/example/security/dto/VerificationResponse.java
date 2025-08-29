package com.example.security.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class VerificationResponse {
    private String message;
    private boolean verified;
    private boolean alreadyVerified;
    private RefreshTokenRequest.AuthenticationResponse authenticationResponse;
}

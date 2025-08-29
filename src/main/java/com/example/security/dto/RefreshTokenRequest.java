package com.example.security.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RefreshTokenRequest {
    private String refreshToken;

    @Data
    @Builder
    @AllArgsConstructor
    @NoArgsConstructor
    public static class AuthenticationRequest {
        String email;
        String password;
    }

    @Data
    @Builder
    @AllArgsConstructor
    @NoArgsConstructor
    public static class AuthenticationResponse {
        String token;
        private String refreshToken;
        private long expiresIn;
        private String tokenType;
    }
}

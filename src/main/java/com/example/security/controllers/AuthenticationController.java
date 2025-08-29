package com.example.security.controllers;

import com.example.security.dto.*;
import com.example.security.services.AuthenticationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import jakarta.validation.Valid;
import java.util.HashMap;
import java.util.Map;

import static com.example.security.constants.utils.APP_ROOT;

@RestController
@CrossOrigin(origins = "*")
@RequiredArgsConstructor
@RequestMapping(APP_ROOT + "/auth")
@Slf4j
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    @PostMapping(value = "/authenticate")
    public ResponseEntity<RefreshTokenRequest.AuthenticationResponse> authenticate(@Valid @RequestBody RefreshTokenRequest.AuthenticationRequest request) {
        return ResponseEntity.ok(authenticationService.authenticate(request));
    }

    /**
     * Inscription utilisateur - MODIFIÉE pour retourner RegisterResponse au lieu d'AuthenticationResponse
     */
    @PostMapping(value = "/registerUser")
    public ResponseEntity<RegisterResponse> registerUser(@Valid @RequestBody RegisterRequest request) {
        RegisterResponse response = authenticationService.register(request);
        return ResponseEntity.ok(response);
    }

    /**
     * NOUVELLE - Vérification de l'email
     */
    @PostMapping(value = "/verify-email")
    public ResponseEntity<VerificationResponse> verifyEmail(@Valid @RequestBody VerificationRequest request) {
        VerificationResponse response = authenticationService.verifyEmail(request.getToken());
        return ResponseEntity.ok(response);
    }

    /**
     * NOUVELLE - Renvoyer l'email de vérification
     */
    @PostMapping(value = "/resend-verification")
    public ResponseEntity<Map<String, String>> resendVerificationEmail(@Valid @RequestBody ResendVerificationRequest request) {
        authenticationService.resendVerificationEmail(request.getEmail());

        Map<String, String> response = new HashMap<>();
        response.put("message", "Email de vérification renvoyé avec succès");
        response.put("email", request.getEmail());

        return ResponseEntity.ok(response);
    }

    /**
     * Inscription admin - garde le même comportement (pas de vérification email pour les admins)
     */
    @PostMapping(value = "/registerAdmin")
    public ResponseEntity<RefreshTokenRequest.AuthenticationResponse> registerAdmin(@Valid @RequestBody RegisterRequest request) {
        return ResponseEntity.ok(authenticationService.registerAdmin(request));
    }

    @PostMapping(value = "/refresh")
    public ResponseEntity<RefreshTokenRequest.AuthenticationResponse> refreshToken(@Valid @RequestBody RefreshTokenRequest request) {
        return ResponseEntity.ok(authenticationService.refreshToken(request));
    }

    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(@RequestHeader(value = "Authorization", required = false) String authHeader) {
        if (authHeader == null || authHeader.isEmpty()) {
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("error", "Token d'autorisation manquant");
            return ResponseEntity.badRequest().body(errorResponse);
        }

        authenticationService.logout(authHeader);

        Map<String, String> response = new HashMap<>();
        response.put("message", "Déconnexion réussie");
        return ResponseEntity.ok(response);
    }

    /**
     * NOUVELLE - Endpoint pour obtenir le statut d'un compte par email
     */
    @GetMapping("/account-status/{email}")
    public ResponseEntity<Map<String, Object>> getAccountStatus(@PathVariable String email) {
        try {
            AccountStatusInfo statusInfo = authenticationService.getAccountStatus(email);

            Map<String, Object> response = new HashMap<>();
            response.put("email", email);
            response.put("exists", statusInfo.isExists());
            response.put("emailVerified", statusInfo.isEmailVerified());
            response.put("accountStatus", statusInfo.getAccountStatus());
            response.put("canResendVerification", statusInfo.isCanResendVerification());

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            Map<String, Object> response = new HashMap<>();
            response.put("email", email);
            response.put("exists", false);
            response.put("error", "Compte non trouvé");

            return ResponseEntity.ok(response);
        }
    }

    /**
     * NOUVELLE - Endpoint de santé pour vérifier l'état du service
     */
    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> healthCheck() {
        Map<String, Object> response = new HashMap<>();
        response.put("status", "UP");
        response.put("service", "Authentication Service");
        response.put("timestamp", System.currentTimeMillis());
        response.put("features", Map.of(
                "emailVerification", true,
                "adminRegistration", true,
                "jwtTokens", true,
                "auditLogs", true
        ));

        return ResponseEntity.ok(response);
    }
}
package com.example.security.controllers;

import com.example.security.configuraton.JwtService;
import com.example.security.dto.*;
import com.example.security.entites.User;
import com.example.security.services.*;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import jakarta.validation.Valid;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.example.security.constants.utils.APP_ROOT;

@RestController
@CrossOrigin(origins = "*")
@RequiredArgsConstructor
@RequestMapping(APP_ROOT + "/auth")
@Slf4j
@Tag(name = "Authentication", description = "Gestion de l'authentification, inscription, sécurité et sessions")
public class AuthenticationController {

    private final AuthenticationService authenticationService;
    private final PasswordService passwordService;
    private final AccountLockoutService lockoutService;
    private final EmailChangeService emailChangeService;
    private final OAuth2Service oAuth2Service;
    private final SessionService sessionService;
    private final JwtService jwtService;

    // =============== AUTHENTIFICATION DE BASE ===============

    @Operation(
            summary = "Authentifier un utilisateur",
            description = "Permet de se connecter avec email et mot de passe. Retourne un token JWT + refresh token."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Authentification réussie"),
            @ApiResponse(responseCode = "401", description = "Identifiants invalides"),
            @ApiResponse(responseCode = "423", description = "Compte temporairement verrouillé")
    })
    @PostMapping(value = "/simple/authenticate")
    public ResponseEntity<RefreshTokenRequest.AuthenticationResponse> authenticate(
            @Valid @RequestBody RefreshTokenRequest.AuthenticationRequest request) {
        return ResponseEntity.ok(authenticationService.authenticate(request));
    }

    @Operation(
            summary = "Inscription utilisateur",
            description = "Crée un nouvel utilisateur standard avec email et mot de passe. Envoie un email de vérification."
    )
    @ApiResponse(responseCode = "200", description = "Utilisateur enregistré avec succès")
    @PostMapping(value = "/simple/registerUser")
    public ResponseEntity<RegisterResponse> registerUser(@Valid @RequestBody RegisterRequest request) {
        RegisterResponse response = authenticationService.register(request);
        return ResponseEntity.ok(response);
    }

    @Operation(
            summary = "Vérifier un email",
            description = "Valide un compte utilisateur via le token de vérification reçu par email."
    )
    @PostMapping(value = "/simple/verify-email")
    public ResponseEntity<VerificationResponse> verifyEmail(@Valid @RequestBody VerificationRequest request) {
        VerificationResponse response = authenticationService.verifyEmail(request.getToken());
        return ResponseEntity.ok(response);
    }

    @Operation(
            summary = "Renvoyer email de vérification",
            description = "Permet de renvoyer l'email de vérification si l'utilisateur n'a pas encore validé son compte."
    )
    @PostMapping(value = "/simple/resend-verification")
    public ResponseEntity<Map<String, String>> resendVerificationEmail(@Valid @RequestBody ResendVerificationRequest request) {
        authenticationService.resendVerificationEmail(request.getEmail());

        Map<String, String> response = new HashMap<>();
        response.put("message", "Email de vérification renvoyé avec succès");
        response.put("email", request.getEmail());

        return ResponseEntity.ok(response);
    }

    @Operation(
            summary = "Inscription administrateur",
            description = "Crée un compte administrateur. Pas de vérification email requise."
    )
    @PostMapping(value = "/sessions/registerAdmin")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public ResponseEntity<RefreshTokenRequest.AuthenticationResponse> registerAdmin(@Valid @RequestBody RegisterRequest request) {
        return ResponseEntity.ok(authenticationService.registerAdmin(request));
    }

    @Operation(
            summary = "Rafraîchir le token JWT",
            description = "Utilise un refresh token valide pour obtenir un nouveau token JWT."
    )
    @PostMapping(value = "/sessions/refresh")
    public ResponseEntity<RefreshTokenRequest.AuthenticationResponse> refreshToken(@Valid @RequestBody RefreshTokenRequest request) {
        return ResponseEntity.ok(authenticationService.refreshToken(request));
    }

    @Operation(
            summary = "Déconnexion",
            description = "Déconnecte l'utilisateur courant en invalidant son token JWT."
    )
    @PostMapping("/sessions/logout")
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

    // =============== INFORMATIONS COMPTE ===============

    @Operation(
            summary = "Statut du compte",
            description = "Retourne les informations d'état d'un compte utilisateur : existe, email vérifié, statut, etc."
    )
    @GetMapping("/sessions/account-status/{email}")
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

    @Operation(
            summary = "Profil utilisateur complet",
            description = "Récupère toutes les informations du profil de l'utilisateur connecté"
    )
    @GetMapping("/sessions/profile")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<UserProfileResponse> getProfile() {
        User currentUser = authenticationService.getCurrentUser();

        UserProfileResponse profile = UserProfileResponse.builder()
                .id(currentUser.getId())
                .email(currentUser.getEmail())
                .name(currentUser.getName())
                .pname(currentUser.getPname())
                .role(currentUser.getRoles().name())
                .accountStatus(currentUser.getAccountStatus().name())
                .emailVerified(currentUser.getEmailVerified())
                .createdAt(currentUser.getCreatedAt())
                .lastLogin(currentUser.getLastSuccessfulLogin())
                .failedLoginAttempts(currentUser.getFailedLoginAttempts())
                .isTemporarilyLocked(currentUser.isTemporarilyLocked())
                .build();

        return ResponseEntity.ok(profile);
    }

    @Operation(
            summary = "Health Check",
            description = "Vérifie l'état du service d'authentification."
    )
    @GetMapping("/simple/health")
    public ResponseEntity<Map<String, Object>> healthCheck() {
        Map<String, Object> response = new HashMap<>();
        response.put("status", "UP");
        response.put("service", "Authentication Service");
        response.put("timestamp", System.currentTimeMillis());
        response.put("features", Map.of(
                "emailVerification", true,
                "adminRegistration", true,
                "jwtTokens", true,
                "auditLogs", true,
                "sessionManagement", true,
                "accountLockout", true,
                "passwordRecovery", true,
                "emailChange", true,
                "oauth2Google", true
        ));

        return ResponseEntity.ok(response);
    }

    // =============== GESTION MOT DE PASSE ===============

    @Operation(
            summary = "Demande de récupération de mot de passe",
            description = "Initie le processus de réinitialisation du mot de passe en envoyant un email avec un lien de récupération"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Email de récupération envoyé"),
            @ApiResponse(responseCode = "404", description = "Email non trouvé")
    })
    @PostMapping("/simple/password/reset-request")
    public ResponseEntity<ResponseDto> requestPasswordReset(@Valid @RequestBody PasswordResetRequest request) {
        ResponseDto response = passwordService.requestPasswordReset(request);
        return ResponseEntity.ok(response);
    }

    @Operation(
            summary = "Confirmation de récupération de mot de passe",
            description = "Finalise la réinitialisation du mot de passe avec le token reçu par email"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Mot de passe réinitialisé avec succès"),
            @ApiResponse(responseCode = "400", description = "Token invalide ou expiré")
    })
    @PostMapping("/simple/password/reset-confirm")
    public ResponseEntity<ResponseDto> confirmPasswordReset(@Valid @RequestBody PasswordResetConfirmRequest request) {
        ResponseDto response = passwordService.confirmPasswordReset(request);
        return ResponseEntity.ok(response);
    }

    @Operation(
            summary = "Changement de mot de passe",
            description = "Permet à un utilisateur connecté de changer son mot de passe actuel"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Mot de passe modifié avec succès"),
            @ApiResponse(responseCode = "400", description = "Ancien mot de passe incorrect")
    })
    @PostMapping("/sessions/password/change")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<ResponseDto> changePassword(@Valid @RequestBody PasswordChangeRequest request) {
        ResponseDto response = passwordService.changePassword(request);
        return ResponseEntity.ok(response);
    }

    @Operation(
            summary = "Vérification de la robustesse du mot de passe",
            description = "Évalue la sécurité d'un mot de passe selon différents critères"
    )
    @PostMapping("/sessions/password/check-strength")
    public ResponseEntity<PasswordStrengthInfo> checkPasswordStrength(@RequestBody Map<String, String> request) {
        String password = request.get("password");
        PasswordStrengthInfo strengthInfo = passwordService.checkPasswordStrength(password);
        return ResponseEntity.ok(strengthInfo);
    }

    // =============== GESTION EMAIL ===============

    @Operation(
            summary = "Demande de changement d'email",
            description = "Initie le processus de changement d'adresse email. Un email de confirmation est envoyé à la nouvelle adresse."
    )
    @PostMapping("/sessions/email/change-request")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<ResponseDto> requestEmailChange(@Valid @RequestBody EmailChangeRequest request) {
        ResponseDto response = emailChangeService.requestEmailChange(request);
        return ResponseEntity.ok(response);
    }

    @Operation(
            summary = "Confirmation du changement d'email",
            description = "Finalise le changement d'email avec le token de confirmation reçu par email"
    )
    @PostMapping("/sessions/email/change-confirm")
    public ResponseEntity<ResponseDto> confirmEmailChange(@Valid @RequestBody EmailChangeConfirmRequest request) {
        ResponseDto response = emailChangeService.confirmEmailChange(request);
        return ResponseEntity.ok(response);
    }

    @Operation(
            summary = "Annulation du changement d'email",
            description = "Annule une demande de changement d'email en cours"
    )
    @PostMapping("/sessions/email/change-cancel")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<ResponseDto> cancelEmailChange() {
        ResponseDto response = emailChangeService.cancelEmailChange();
        return ResponseEntity.ok(response);
    }

    @Operation(
            summary = "Statut du changement d'email",
            description = "Récupère l'état actuel d'une demande de changement d'email"
    )
    @GetMapping("/sessions/email/change-status")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<EmailChangeStatus> getEmailChangeStatus() {
        EmailChangeStatus status = emailChangeService.getEmailChangeStatus();
        return ResponseEntity.ok(status);
    }

    @Operation(
            summary = "Validation d'adresse email",
            description = "Vérifie la validité et la disponibilité d'une adresse email"
    )
    @PostMapping("/sessions/email/validate")
    public ResponseEntity<EmailValidationResult> validateEmail(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        EmailValidationResult result = emailChangeService.validateEmail(email);
        return ResponseEntity.ok(result);
    }

    // =============== AUTHENTIFICATION OAUTH2 ===============

    @Operation(
            summary = "Authentification Google OAuth2",
            description = "Connecte ou crée un utilisateur via Google OAuth2"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Authentification Google réussie"),
            @ApiResponse(responseCode = "400", description = "Token Google invalide")
    })
    @PostMapping("/simple/oauth2/google")
    public ResponseEntity<RefreshTokenRequest.AuthenticationResponse> authenticateWithGoogle(@Valid @RequestBody OAuth2LoginRequest request) throws Exception {
        RefreshTokenRequest.AuthenticationResponse response = oAuth2Service.authenticateWithGoogle(request);
        return ResponseEntity.ok(response);
    }

    // =============== GESTION DES SESSIONS ===============

    @Operation(
            summary = "Sessions actives de l'utilisateur",
            description = "Récupère la liste de toutes les sessions actives de l'utilisateur connecté"
    )
    @GetMapping("/sessions/all-sessions")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<List<SessionInfo>> getActiveSessions(@RequestHeader(value = "Authorization") String authHeader) {
        String currentSessionId = authenticationService.extractSessionIdFromAuth(authHeader);
        User currentUser = authenticationService.getCurrentUser();

        List<SessionInfo> sessions = sessionService.getActiveSessions(currentUser, currentSessionId);
        return ResponseEntity.ok(sessions);
    }

    @Operation(
            summary = "Fermer une session spécifique",
            description = "Ferme une session particulière identifiée par son ID"
    )
    @PostMapping("/sessions/{sessionId}/logout")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<Map<String, String>> logoutSession(@PathVariable String sessionId) {
        boolean success = sessionService.logoutSession(sessionId, "USER_LOGOUT_SPECIFIC");

        Map<String, String> response = new HashMap<>();
        if (success) {
            response.put("message", "Session fermée avec succès");
        } else {
            response.put("error", "Session introuvable ou déjà fermée");
        }

        return ResponseEntity.ok(response);
    }

    @Operation(
            summary = "Fermer toutes les autres sessions",
            description = "Ferme toutes les sessions actives de l'utilisateur sauf la session courante"
    )
    @PostMapping("/sessions/logout-all-others")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> logoutAllOtherSessions(@RequestHeader(value = "Authorization") String authHeader) {
        String currentSessionId = authenticationService.extractSessionIdFromAuth(authHeader);
        User currentUser = authenticationService.getCurrentUser();

        int loggedOutCount = sessionService.logoutAllOtherSessions(currentUser, currentSessionId);

        Map<String, Object> response = new HashMap<>();
        response.put("message", loggedOutCount + " sessions fermées");
        response.put("loggedOutCount", loggedOutCount);

        return ResponseEntity.ok(response);
    }

    // =============== INFORMATIONS DE SÉCURITÉ ===============

    @Operation(
            summary = "Informations de verrouillage de compte",
            description = "Récupère les détails de verrouillage d'un compte utilisateur"
    )
    @GetMapping("/sessions/lockout-info/{email}")
    public ResponseEntity<LockoutInfo> getLockoutInfo(@PathVariable String email) {
        LockoutInfo lockoutInfo = lockoutService.getLockoutInfo(email);
        return ResponseEntity.ok(lockoutInfo);
    }

    // =============== ADMINISTRATION ===============

    @Operation(
            summary = "Déverrouiller un compte (Admin)",
            description = "Permet à un administrateur de déverrouiller manuellement un compte utilisateur"
    )
    @PostMapping("/sessions/admin/unlock-account")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, String>> unlockAccount(
            @RequestBody Map<String, String> request) {

        String email = request.get("email");
        String reason = request.get("reason");
        User currentUser = authenticationService.getCurrentUser();

        boolean success = lockoutService.unlockAccount(email, currentUser.getEmail(), reason);

        Map<String, String> response = new HashMap<>();
        if (success) {
            response.put("message", "Compte déverrouillé avec succès");
        } else {
            response.put("error", "Compte non trouvé ou erreur");
        }

        return ResponseEntity.ok(response);
    }

    @Operation(
            summary = "Statistiques de sécurité (Admin)",
            description = "Fournit des statistiques détaillées sur la sécurité du système"
    )
    @GetMapping("/sessions/admin/security-stats")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<SecurityStats> getSecurityStats() {
        SecurityStats stats = lockoutService.getSecurityStats();
        return ResponseEntity.ok(stats);
    }

    @Operation(
            summary = "Liste des utilisateurs (Admin)",
            description = "Récupère la liste paginée de tous les utilisateurs"
    )
    @GetMapping("/sessions/admin/users")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<PagedResponse<UserSummaryDto>> getUsers(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(defaultValue = "createdAt") String sortBy,
            @RequestParam(defaultValue = "desc") String sortDir,
            @RequestParam(required = false) String search) {

        PagedResponse<UserSummaryDto> users = authenticationService.getUsers(page, size, sortBy, sortDir, search);
        return ResponseEntity.ok(users);
    }

    @Operation(
            summary = "Détails d'un utilisateur (Admin)",
            description = "Récupère les détails complets d'un utilisateur spécifique"
    )
    @GetMapping("/sessions/admin/users/{userId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<AdminUserDetailDto> getUserDetails(@PathVariable Long userId) {
        AdminUserDetailDto userDetails = authenticationService.getUserDetails(userId);
        return ResponseEntity.ok(userDetails);
    }

    @Operation(
            summary = "Modifier le statut d'un compte (Admin)",
            description = "Permet de changer le statut d'un compte utilisateur (actif, suspendu, banni)"
    )
    @PostMapping("/sessions/admin/users/{userId}/status")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ResponseDto> updateUserStatus(
            @PathVariable Long userId,
            @RequestBody UserStatusUpdateRequest request) {

        User currentAdmin = authenticationService.getCurrentUser();
        ResponseDto response = authenticationService.updateUserStatus(userId, request, currentAdmin.getEmail());
        return ResponseEntity.ok(response);
    }

    // Dans la section GESTION DE VERROUILLAGE
    @Operation(
            summary = "Enregistrer une tentative de connexion",
            description = "Enregistre une tentative de connexion (succès/échec) pour le système de verrouillage"
    )
    @PostMapping("/sessions/record-login-attempt")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, String>> recordLoginAttempt(
            @RequestBody Map<String, Object> request,
            HttpServletRequest httpRequest) {

        String email = (String) request.get("email");
        String ipAddress = (String) request.get("ipAddress");
        Boolean success = (Boolean) request.get("success");
        String failureReason = (String) request.get("failureReason");

        lockoutService.recordLoginAttempt(email, ipAddress, success, failureReason, httpRequest);

        Map<String, String> response = new HashMap<>();
        response.put("message", "Tentative de connexion enregistrée");
        return ResponseEntity.ok(response);
    }

    @Operation(
            summary = "Vérifier si un compte est verrouillé",
            description = "Vérifie si un compte utilisateur est temporairement verrouillé"
    )
    @GetMapping("/sessions/is-locked/{email}")
    public ResponseEntity<Map<String, Boolean>> isAccountLocked(@PathVariable String email) {
        boolean isLocked = lockoutService.isAccountLocked(email);

        Map<String, Boolean> response = new HashMap<>();
        response.put("isLocked", isLocked);
        return ResponseEntity.ok(response);
    }

    @Operation(
            summary = "Envoyer notification d'activité suspecte",
            description = "Envoie une notification pour activité suspecte détectée"
    )
    @PostMapping("/sessions/admin/send-suspicious-activity-notification")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, String>> sendSuspiciousActivityNotification(
            @RequestBody Map<String, Object> request) {

        String ipAddress = (String) request.get("ipAddress");
        Long failureCount = Long.valueOf(request.get("failureCount").toString());
        String userEmail = (String) request.get("userEmail");

        lockoutService.sendSuspiciousActivityNotification(ipAddress, failureCount, userEmail);

        Map<String, String> response = new HashMap<>();
        response.put("message", "Notification d'activité suspecte envoyée");
        return ResponseEntity.ok(response);
    }

    @Operation(
            summary = "Envoyer alerte de sécurité",
            description = "Envoie une alerte de sécurité pour tentatives multiples"
    )
    @PostMapping("/sessions/admin/send-security-alert")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, String>> sendSecurityAlert(
            @RequestBody Map<String, Object> request) {

        String email = (String) request.get("email");
        Integer failedAttempts = (Integer) request.get("failedAttempts");
        Integer remainingAttempts = (Integer) request.get("remainingAttempts");

        lockoutService.sendSecurityAlert(email, failedAttempts, remainingAttempts);

        Map<String, String> response = new HashMap<>();
        response.put("message", "Alerte de sécurité envoyée");
        return ResponseEntity.ok(response);
    }

// =============== GESTION CLEANUP ACCOUNTS ===============

    @Operation(
            summary = "Forcer le nettoyage des comptes non vérifiés",
            description = "Force le nettoyage manuel des comptes non vérifiés plus anciens que X jours"
    )
    @PostMapping("/sessions/admin/force-cleanup")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<CleanupResult> forceAccountCleanup(
            @RequestBody Map<String, Integer> request) {

        Integer daysOld = request.get("daysOld");
        if (daysOld == null || daysOld < 1) {
            throw new IllegalArgumentException("Le nombre de jours doit être supérieur à 0");
        }

        // Injection du service AccountCleanupService nécessaire
        // CleanupResult result = accountCleanupService.forceCleanup(daysOld);

        // Temporaire - remplacer par l'appel réel
        CleanupResult result = CleanupResult.builder()
                .deletedCount(0)
                .cutoffDate(java.time.LocalDateTime.now().minusDays(daysOld))
                .emails(java.util.Collections.emptyList())
                .build();

        return ResponseEntity.ok(result);
    }

// =============== GESTION SESSIONS AVANCÉE ===============

    @Operation(
            summary = "Statistiques des sessions",
            description = "Récupère les statistiques détaillées des sessions"
    )
    @GetMapping("/sessions/admin/session-stats")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<SessionStats> getSessionStats() {
        SessionStats stats = sessionService.getSessionStats();
        return ResponseEntity.ok(stats);
    }

    @Operation(
            summary = "Vérifier la validité d'une session",
            description = "Vérifie si une session spécifique est toujours valide"
    )
    @GetMapping("/sessions/validate/{sessionId}")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<Map<String, Boolean>> validateSession(@PathVariable String sessionId) {
        boolean isValid = sessionService.isSessionValid(sessionId);

        Map<String, Boolean> response = new HashMap<>();
        response.put("isValid", isValid);
        return ResponseEntity.ok(response);
    }

    @Operation(
            summary = "Mettre à jour l'activité de session",
            description = "Met à jour le timestamp de dernière activité d'une session"
    )
    @PostMapping("/sessions/update-activity/{sessionId}")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<Map<String, String>> updateSessionActivity(@PathVariable String sessionId) {
        sessionService.updateSessionActivity(sessionId);

        Map<String, String> response = new HashMap<>();
        response.put("message", "Activité de session mise à jour");
        return ResponseEntity.ok(response);
    }

    @Operation(
            summary = "Créer une session avec token",
            description = "Crée une nouvelle session et retourne le token JWT associé"
    )
    @PostMapping("/sessions/create-with-token")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<Map<String, String>> createSessionWithToken(
            @RequestBody Map<String, String> request,
            HttpServletRequest httpRequest) {

        User currentUser = authenticationService.getCurrentUser();
        String deviceInfo = request.get("deviceInfo");

        String token = sessionService.createSessionWithToken(currentUser, httpRequest, deviceInfo);

        Map<String, String> response = new HashMap<>();
        response.put("token", token);
        response.put("message", "Session créée avec succès");
        return ResponseEntity.ok(response);
    }

    @Operation(
            summary = "Tester les notifications",
            description = "Envoie des notifications de test pour vérifier la configuration"
    )
    @PostMapping("/sessions/admin/test-notifications")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, String>> testNotifications(
            @RequestBody Map<String, String> request) {

        String email = request.get("email");
        String notificationType = request.get("type");

        // Logique pour envoyer différents types de notifications de test
        // Ceci nécessiterait d'étendre les services existants

        Map<String, String> response = new HashMap<>();
        response.put("message", "Notification de test envoyée à " + email);
        response.put("type", notificationType);
        return ResponseEntity.ok(response);
    }

// =============== ENDPOINTS DE DEBUGGING (DÉVELOPPEMENT UNIQUEMENT) ===============

    @Operation(
            summary = "Informations de debug JWT",
            description = "Retourne les informations contenues dans un token JWT (dev uniquement)"
    )
    @PostMapping("/sessions/debug/jwt-info")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> getJwtInfo(
            @RequestBody Map<String, String> request) {

        String token = request.get("token");

        try {
            String email = jwtService.extractuserEmail(token);
            String sessionId = jwtService.extractClaim(token, claims -> (String) claims.get("sessionId"));
            Boolean isBlacklisted = jwtService.isTokenBlacklisted(token);

            Map<String, Object> response = new HashMap<>();
            response.put("email", email);
            response.put("sessionId", sessionId);
            response.put("isBlacklisted", isBlacklisted);
            response.put("isValid", jwtService.isTokenValid(token, authenticationService.findUserByEmail(email)));

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            Map<String, Object> response = new HashMap<>();
            response.put("error", "Token invalide");
            response.put("message", e.getMessage());
            return ResponseEntity.badRequest().body(response);
        }
    }

}

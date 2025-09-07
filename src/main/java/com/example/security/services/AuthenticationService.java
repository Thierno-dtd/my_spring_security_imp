package com.example.security.services;

import com.example.security.configuraton.JwtService;
import com.example.security.constants.AccountStatus;
import com.example.security.constants.TypeRoles;
import com.example.security.dto.*;
import com.example.security.entites.LoginAttempt;
import com.example.security.entites.User;
import com.example.security.module.notifications.NotificationClient;
import com.example.security.outils.DataEncryption;
import com.example.security.repositories.LoginAttemptRepository;
import com.example.security.repositories.UserRepository;
import com.example.security.module.auditsLogs.AuditMicroserviceClient;
import jakarta.persistence.EntityNotFoundException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@Slf4j
@RequiredArgsConstructor
public class AuthenticationService {

    @Value("${jwt.expiration}")
    private String jwtExpiration;
    @Value("${jwt.token-type}")
    private String tokenType;
    @Value("${email.verification.expiration:24}")
    private int emailVerificationExpirationHours;

    private final SessionService sessionService;
    private final LoginAttemptRepository loginAttemptRepository;
    private final UserRepository utilisateurRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuditMicroserviceClient auditMicroserviceClient;
    private final NotificationClient notificationClient;
    private final DataEncryption dataEncryption;
    private final AccountLockoutService accountLockoutService;

    /**
     * Étape 1: Inscription avec envoi d'email de vérification
     */
    public RegisterResponse register(RegisterRequest request) {
        long startTime = System.currentTimeMillis();
        HttpServletRequest httpRequest = getCurrentHttpRequest();
        String clientIp = extractClientIp(httpRequest);

        try {
            // AUDIT: Début de processus d'inscription
            auditMicroserviceClient.logAuditEvent(
                    "USER_REGISTRATION_STARTED",
                    request.getEmail(),
                    "Début processus inscription depuis IP: " + clientIp,
                    httpRequest,
                    0L
            );

            // Vérifier si l'email existe déjà
            Optional<User> existingUser = utilisateurRepository.findByEmail(request.getEmail());
            if (existingUser.isPresent()) {
                User existing = existingUser.get();

                // AUDIT: Tentative de réinscription
                auditMicroserviceClient.logSecurityEvent(
                        "DUPLICATE_REGISTRATION_ATTEMPT",
                        request.getEmail(),
                        "MEDIUM",
                        String.format("Tentative réinscription. Compte existant: status=%s, verified=%s, created=%s",
                                existing.getAccountStatus(), existing.getEmailVerified(), existing.getCreatedAt()),
                        httpRequest
                );

                throw new IllegalArgumentException("Un compte avec cet email existe déjà");
            }

            // Validation de l'email
            /*if (!isValidEmailDomain(request.getEmail())) {
                auditMicroserviceClient.logSecurityEvent(
                        "REGISTRATION_INVALID_EMAIL_DOMAIN",
                        request.getEmail(),
                        "LOW",
                        "Tentative inscription avec domaine email invalide ou suspect",
                        httpRequest
                );
            }*/

            // Générer le token de vérification
            String verificationToken = generateVerificationToken();
            LocalDateTime expiresAt = LocalDateTime.now().plusHours(emailVerificationExpirationHours);

            // Créer l'utilisateur
            var user = User.builder()
                    .name(dataEncryption.encryptSensitiveData(request.getName()))
                    .pname(dataEncryption.encryptSensitiveData(request.getPname()))
                    .email(request.getEmail())
                    .passwd(passwordEncoder.encode(request.getPasswd()))
                    .createdByAdmin(getCurrentUser())
                    .roles(TypeRoles.USER)
                    .emailVerified(false)
                    .emailVerificationToken(verificationToken)
                    .emailVerificationExpiresAt(expiresAt)
                    .accountStatus(AccountStatus.PENDING_VERIFICATION)
                    .lastLoginIp(clientIp)
                    .build();

            utilisateurRepository.save(user);

            // AUDIT: Utilisateur créé avec succès
            long executionTime = System.currentTimeMillis() - startTime;
            auditMicroserviceClient.logAuditEvent(
                    "USER_CREATED_PENDING_VERIFICATION",
                    request.getEmail(),
                    String.format("Utilisateur créé. IP: %s, expires: %s", clientIp, expiresAt),
                    httpRequest,
                    executionTime
            );

            // Envoyer l'email de vérification
            try {
                notificationClient.sendEmailVerification(
                        request.getEmail(),
                        request.getName(),
                        verificationToken
                );

                // AUDIT: Email envoyé
                auditMicroserviceClient.logAuditEvent(
                        "VERIFICATION_EMAIL_SENT",
                        request.getEmail(),
                        "Email de vérification envoyé avec succès",
                        httpRequest,
                        0L
                );

            } catch (Exception emailError) {
                // AUDIT: Erreur envoi email
                auditMicroserviceClient.logSecurityEvent(
                        "VERIFICATION_EMAIL_FAILED",
                        request.getEmail(),
                        "MEDIUM",
                        "Échec envoi email de vérification: " + emailError.getMessage(),
                        httpRequest
                );
            }

            log.info("Utilisateur créé en attente de vérification: {}", request.getEmail());

            return RegisterResponse.builder()
                    .message("Inscription réussie! Veuillez vérifier votre email pour activer votre compte.")
                    .emailSent(true)
                    .verificationRequired(true)
                    .build();

        } catch (Exception e) {
            long executionTime = System.currentTimeMillis() - startTime;
            auditMicroserviceClient.logSecurityEvent(
                    "USER_REGISTRATION_FAILED",
                    request.getEmail(),
                    "HIGH",
                    String.format("Échec inscription depuis IP %s: %s", clientIp, e.getMessage()),
                    httpRequest
            );

            log.error("Échec d'enregistrement pour: {}", request.getEmail(), e);
            throw e;
        }
    }

    public RefreshTokenRequest.AuthenticationResponse registerAdmin(RegisterRequest request) {
        long startTime = System.currentTimeMillis();
        HttpServletRequest httpRequest = getCurrentHttpRequest();

        try {
            var user = User.builder()
                    .name(dataEncryption.encryptSensitiveData(request.getName()))
                    .pname(dataEncryption.encryptSensitiveData(request.getPname()))
                    .email(request.getEmail())
                    .passwd(passwordEncoder.encode(request.getPasswd()))
                    .createdByAdmin(getCurrentUser())
                    .roles(TypeRoles.ADMIN)
                    .build();

            utilisateurRepository.save(user);
            var refreshToken = jwtService.generateRefreshToken(user);
            var jwtToken = jwtService.generateToken(user);

            // AUDIT CRITIQUE POUR ADMIN
            long executionTime = System.currentTimeMillis() - startTime;
            auditMicroserviceClient.logAuditEvent(
                    "ADMIN_REGISTRATION_SUCCESS",
                    request.getEmail(),
                    "Nouvel administrateur enregistré",
                    httpRequest,
                    executionTime
            );

            auditMicroserviceClient.logSecurityEvent(
                    "ADMIN_ACCOUNT_CREATED",
                    request.getEmail(),
                    "HIGH",
                    "Création d'un compte administrateur",
                    httpRequest
            );

            log.warn("🔐 Administrateur créé: {}", request.getEmail());

            return RefreshTokenRequest.AuthenticationResponse.builder()
                    .token(jwtToken)
                    .refreshToken(refreshToken)
                    .expiresIn(Long.valueOf(jwtExpiration))
                    .tokenType(tokenType)
                    .build();

        } catch (Exception e) {
            long executionTime = System.currentTimeMillis() - startTime;
            auditMicroserviceClient.logSecurityEvent(
                    "ADMIN_REGISTRATION_FAILED",
                    request.getEmail(),
                    "CRITICAL",
                    "Tentative de création d'admin échouée: " + e.getMessage(),
                    httpRequest
            );
            throw e;
        }
    }

    /**
     * Renvoyer l'email de vérification
     */
    public void resendVerificationEmail(String email) {
        User user = utilisateurRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("Utilisateur non trouvé"));

        if (user.getEmailVerified()) {
            throw new IllegalArgumentException("Email déjà vérifié");

        }

        // Générer un nouveau token
        String verificationToken = generateVerificationToken();
        LocalDateTime expiresAt = LocalDateTime.now().plusHours(emailVerificationExpirationHours);

        user.setEmailVerificationToken(verificationToken);
        user.setEmailVerificationExpiresAt(expiresAt);
        utilisateurRepository.save(user);

        // Renvoyer l'email
        String decryptedName = dataEncryption.decryptSensitiveData(user.getName());
        notificationClient.sendEmailVerification(email, decryptedName, verificationToken);

        log.info("📧 Email de vérification renvoyé pour: {}", email);
    }

    /**
     * Étape 2: Vérification de l'email et activation du compte
     */

    public VerificationResponse verifyEmail(String verificationToken) {
        long startTime = System.currentTimeMillis();
        HttpServletRequest httpRequest = getCurrentHttpRequest();

        try {
            User user = utilisateurRepository.findByEmailVerificationToken(verificationToken)
                    .orElseThrow(() -> new IllegalArgumentException("Token de vérification invalide"));

            // Vérifier l'expiration du token
            if (user.getEmailVerificationExpiresAt().isBefore(LocalDateTime.now())) {
                auditMicroserviceClient.logSecurityEvent(
                        "EMAIL_VERIFICATION_EXPIRED",
                        user.getEmail(),
                        "MEDIUM",
                        "Tentative de vérification avec token expiré",
                        httpRequest
                );
                throw new IllegalArgumentException("Le token de vérification a expiré");
            }

            // Vérifier si déjà vérifié
            if (user.getEmailVerified()) {
                return VerificationResponse.builder()
                        .message("Email déjà vérifié")
                        .alreadyVerified(true)
                        .build();
            }

            // Activer le compte
            user.setEmailVerified(true);
            user.setEmailVerificationToken(null);
            user.setEmailVerificationExpiresAt(null);
            user.setAccountStatus(AccountStatus.ACTIVE);

            utilisateurRepository.save(user);

            // Envoyer email de bienvenue
            String decryptedName = dataEncryption.decryptSensitiveData(user.getName());
            notificationClient.sendWelcomeEmail(user.getEmail(), decryptedName);

            // Générer les tokens JWT pour connexion automatique
            var refreshToken = jwtService.generateRefreshToken(user);
            var jwtToken = jwtService.generateToken(user);

            // AUDIT
            long executionTime = System.currentTimeMillis() - startTime;
            auditMicroserviceClient.logAuditEvent(
                    "EMAIL_VERIFICATION_SUCCESS",
                    user.getEmail(),
                    "Email vérifié avec succès, compte activé",
                    httpRequest,
                    executionTime
            );

            log.info("✅ Email vérifié et compte activé pour: {}", user.getEmail());

            return VerificationResponse.builder()
                    .message("Email vérifié avec succès! Votre compte est maintenant actif.")
                    .verified(true)
                    .authenticationResponse(RefreshTokenRequest.AuthenticationResponse.builder()
                            .token(jwtToken)
                            .refreshToken(refreshToken)
                            .expiresIn(Long.valueOf(jwtExpiration))
                            .tokenType(tokenType)
                            .build())
                    .build();

        } catch (Exception e) {
            auditMicroserviceClient.logSecurityEvent(
                    "EMAIL_VERIFICATION_FAILED",
                    "unknown",
                    "MEDIUM",
                    "Échec de vérification email: " + e.getMessage(),
                    httpRequest
            );
            log.error("❌ Échec de vérification email", e);
            throw e;
        }
    }

    public RefreshTokenRequest.AuthenticationResponse authenticate(RefreshTokenRequest.AuthenticationRequest request) {
        long startTime = System.currentTimeMillis();
        HttpServletRequest httpRequest = getCurrentHttpRequest();
        String clientIp = extractClientIp(httpRequest);
        String userAgent = httpRequest.getHeader("User-Agent");

        // AUDIT: Début de tentative de connexion
        auditMicroserviceClient.logAuditEvent(
                "LOGIN_ATTEMPT_STARTED",
                request.getEmail(),
                String.format("Tentative connexion depuis IP: %s, UserAgent: %s", clientIp, userAgent),
                httpRequest,
                0L
        );

        try {
            User user = (User) utilisateurRepository.findByEmail(request.getEmail())
                    .orElseThrow(() -> {
                        // AUDIT: Utilisateur inexistant
                        auditMicroserviceClient.logSecurityEvent(
                                "LOGIN_ATTEMPT_UNKNOWN_USER",
                                request.getEmail(),
                                "MEDIUM",
                                String.format("Tentative connexion avec email inexistant depuis IP: %s", clientIp),
                                httpRequest
                        );
                        return new EntityNotFoundException("Identifiants invalides");
                    });

            // AUDIT: Utilisateur trouvé - informations de contexte
            auditMicroserviceClient.logAuditEvent(
                    "LOGIN_USER_IDENTIFIED",
                    request.getEmail(),
                    String.format("Utilisateur identifié. Status: %s, LastLogin: %s, FailedAttempts: %d",
                            user.getAccountStatus(), user.getLastSuccessfulLogin(), user.getFailedLoginAttempts()),
                    httpRequest,
                    0L
            );

            // Vérifications de sécurité avec audit
            if (!user.getEmailVerified()) {
                auditMicroserviceClient.logSecurityEvent(
                        "LOGIN_ATTEMPT_UNVERIFIED_EMAIL",
                        request.getEmail(),
                        "MEDIUM",
                        "Tentative connexion avec email non vérifié",
                        httpRequest
                );
                throw new IllegalArgumentException("Veuillez d'abord vérifier votre email");
            }

            if (user.getAccountStatus() != AccountStatus.ACTIVE) {
                auditMicroserviceClient.logSecurityEvent(
                        "LOGIN_ATTEMPT_INACTIVE_ACCOUNT",
                        request.getEmail(),
                        "HIGH",
                        String.format("Tentative connexion compte inactif/suspendu: %s", user.getAccountStatus()),
                        httpRequest
                );
                throw new IllegalArgumentException("Compte inactif ou suspendu");
            }

            if (user.isTemporarilyLocked()) {
                auditMicroserviceClient.logSecurityEvent(
                        "LOGIN_ATTEMPT_LOCKED_ACCOUNT",
                        request.getEmail(),
                        "HIGH",
                        String.format("Tentative connexion compte verrouillé jusqu'à: %s", user.getLockedUntil()),
                        httpRequest
                );
                throw new IllegalArgumentException("Compte temporairement verrouillé");
            }

            // Vérification du mot de passe
            if (passwordEncoder.matches(request.getPassword(), user.getPassword())) {
                // SUCCÈS DE CONNEXION
                String jwtToken = jwtService.generateToken(user);
                String refreshToken = jwtService.generateRefreshToken(user);

                // Mise à jour des informations de connexion
                LocalDateTime lastLogin = user.getLastSuccessfulLogin();
                user.setLastLoginIp(clientIp);
                user.setLastSuccessfulLogin(LocalDateTime.now());
                user.resetFailedLoginAttempts();
                utilisateurRepository.save(user);

                long executionTime = System.currentTimeMillis() - startTime;

                // AUDIT: Connexion réussie avec contexte
                auditMicroserviceClient.logAuditEvent(
                        "USER_LOGIN_SUCCESS",
                        request.getEmail(),
                        String.format("Connexion réussie. IP: %s, LastLogin précédent: %s, Durée: %dms",
                                clientIp, lastLogin, executionTime),
                        httpRequest,
                        executionTime
                );

                // AUDIT: Détection de connexion suspecte (IP différente)
                if (user.getLastLoginIp() != null && !user.getLastLoginIp().equals(clientIp)) {
                    auditMicroserviceClient.logSecurityEvent(
                            "LOGIN_FROM_NEW_IP",
                            request.getEmail(),
                            "MEDIUM",
                            String.format("Connexion depuis nouvelle IP. Précédente: %s, Actuelle: %s",
                                    user.getLastLoginIp(), clientIp),
                            httpRequest
                    );
                }

                // AUDIT: Détection de connexion après longue absence
                if (lastLogin != null && lastLogin.isBefore(LocalDateTime.now().minusDays(30))) {
                    auditMicroserviceClient.logSecurityEvent(
                            "LOGIN_AFTER_LONG_ABSENCE",
                            request.getEmail(),
                            "LOW",
                            String.format("Connexion après %d jours d'absence",
                                    java.time.Duration.between(lastLogin, LocalDateTime.now()).toDays()),
                            httpRequest
                    );
                }

                log.info("Connexion réussie pour: {} depuis {}", request.getEmail(), clientIp);

                return RefreshTokenRequest.AuthenticationResponse.builder()
                        .token(jwtToken)
                        .refreshToken(refreshToken)
                        .expiresIn(Long.valueOf(jwtExpiration))
                        .tokenType(tokenType)
                        .build();

            } else {
                // ÉCHEC - Mot de passe incorrect
                long executionTime = System.currentTimeMillis() - startTime;

                auditMicroserviceClient.logSecurityEvent(
                        "LOGIN_FAILED_WRONG_PASSWORD",
                        request.getEmail(),
                        "HIGH",
                        String.format("Mot de passe incorrect depuis IP: %s, UserAgent: %s",
                                clientIp, userAgent),
                        httpRequest
                );

                // Enregistrer la tentative pour le service de verrouillage

                accountLockoutService.recordLoginAttempt(request.getEmail(), clientIp, false, "WRONG_PASSWORD", httpRequest);

                log.warn("Mot de passe incorrect pour: {} depuis {}", request.getEmail(), clientIp);
                throw new EntityNotFoundException("Identifiants invalides");
            }

        } catch (Exception e) {
            long executionTime = System.currentTimeMillis() - startTime;

            auditMicroserviceClient.logAuditEvent(
                    "USER_LOGIN_ERROR",
                    request.getEmail(),
                    String.format("Erreur authentification depuis IP %s après %dms: %s",
                            clientIp, executionTime, e.getMessage()),
                    httpRequest,
                    executionTime
            );

            log.error("Erreur d'authentification pour: {} depuis {}", request.getEmail(), clientIp, e);
            throw e;
        }
    }

    public RefreshTokenRequest.AuthenticationResponse refreshToken(RefreshTokenRequest request) {
        long startTime = System.currentTimeMillis();
        HttpServletRequest httpRequest = getCurrentHttpRequest();

        try {
            String refreshToken = request.getRefreshToken();
            String userEmail = jwtService.extractuserEmail(refreshToken);

            UserDetails user = utilisateurRepository.findByEmail(userEmail)
                    .orElseThrow(() -> new EntityNotFoundException("Utilisateur non trouvé"));

            String newAccessToken = jwtService.refreshAccessToken(refreshToken, user);

            // AUDIT
            long executionTime = System.currentTimeMillis() - startTime;
            auditMicroserviceClient.logAuditEvent(
                    "TOKEN_REFRESH_SUCCESS",
                    userEmail,
                    "Token rafraîchi avec succès",
                    httpRequest,
                    executionTime
            );

            return RefreshTokenRequest.AuthenticationResponse.builder()
                    .token(newAccessToken)
                    .refreshToken(refreshToken)
                    .expiresIn(Long.valueOf(jwtExpiration))
                    .tokenType(tokenType)
                    .build();

        } catch (Exception e) {
            auditMicroserviceClient.logSecurityEvent(
                    "TOKEN_REFRESH_FAILED",
                    "unknown",
                    "MEDIUM",
                    "Échec de rafraîchissement de token: " + e.getMessage(),
                    httpRequest
            );
            throw e;
        }
    }

    /**
     * Déconnexion avec audit renforcé
     */
    public void logout(String authHeader) {
        HttpServletRequest httpRequest = getCurrentHttpRequest();
        String clientIp = extractClientIp(httpRequest);

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);

            try {
                String userEmail = jwtService.extractuserEmail(token);
                String sessionId = extractSessionIdFromAuth(authHeader);

                // AUDIT: Début de déconnexion
                auditMicroserviceClient.logAuditEvent(
                        "LOGOUT_STARTED",
                        userEmail,
                        String.format("Début déconnexion depuis IP: %s, Session: %s", clientIp, sessionId),
                        httpRequest,
                        0L
                );

                // Blacklister le token
                jwtService.blacklistToken(token);

                // Fermer la session si elle existe
                if (sessionId != null) {
                    // sessionService.logoutSession(sessionId, "USER_LOGOUT");
                }

                // AUDIT: Déconnexion réussie
                auditMicroserviceClient.logAuditEvent(
                        "USER_LOGOUT_SUCCESS",
                        userEmail,
                        String.format("Déconnexion réussie. IP: %s, Token blacklisté, Session fermée: %s",
                                clientIp, sessionId),
                        httpRequest,
                        0L
                );

                log.info("Utilisateur déconnecté: {} depuis {}", userEmail, clientIp);

            } catch (Exception e) {
                auditMicroserviceClient.logSecurityEvent(
                        "LOGOUT_ERROR",
                        "unknown",
                        "MEDIUM",
                        String.format("Erreur déconnexion depuis IP %s: %s", clientIp, e.getMessage()),
                        httpRequest
                );
                throw e;
            }
        } else {
            auditMicroserviceClient.logSecurityEvent(
                    "LOGOUT_INVALID_TOKEN",
                    "unknown",
                    "MEDIUM",
                    String.format("Tentative déconnexion token invalide depuis IP: %s", clientIp),
                    httpRequest
            );

            log.warn("Tentative de logout avec header Authorization invalide depuis {}", clientIp);
            throw new IllegalArgumentException("Header Authorization invalide");
        }
    }
    // MÉTHODE UTILITAIRE AJOUTÉE

    private String generateVerificationToken() {
        return UUID.randomUUID().toString() + "-" + System.currentTimeMillis();
    }

    private HttpServletRequest getCurrentHttpRequest() {
        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        return attributes != null ? attributes.getRequest() : null;
    }

    /**
     * Obtenir le statut d'un compte par email
     */

    public AccountStatusInfo getAccountStatus(String email) {
        Optional<User> userOptional = utilisateurRepository.findByEmail(email);

        if (userOptional.isEmpty()) {
            return AccountStatusInfo.builder()
                    .exists(false)
                    .emailVerified(false)
                    .canResendVerification(false)
                    .build();
        }

        User user = userOptional.get();

        return AccountStatusInfo.builder()
                .exists(true)
                .emailVerified(user.getEmailVerified())
                .accountStatus(user.getAccountStatus())
                .canResendVerification(!user.getEmailVerified() &&
                        (user.getEmailVerificationExpiresAt() == null ||
                                user.getEmailVerificationExpiresAt().isBefore(LocalDateTime.now())))
                .role(user.getRoles())
                .build();
    }

    public User findUserByEmail(String email) {
        return utilisateurRepository.findByEmail(email)
                .orElseThrow(() -> new EntityNotFoundException("Utilisateur non trouvé: " + email));
    }

    public PagedResponse<UserSummaryDto> getUsers(int page, int size, String sortBy, String sortDir, String search) {
        Pageable pageable = PageRequest.of(page, size,
                sortDir.equalsIgnoreCase("desc") ? Sort.by(sortBy).descending() : Sort.by(sortBy).ascending());

        Page<User> usersPage;
        if (search != null && !search.trim().isEmpty()) {
            usersPage = utilisateurRepository.findByEmailContainingOrNameContainingIgnoreCase(search, search, pageable);
        } else {
            usersPage = utilisateurRepository.findAll(pageable);
        }

        List<UserSummaryDto> userSummaries = usersPage.getContent().stream()
                .map(this::mapToUserSummary)
                .collect(Collectors.toList());

        return PagedResponse.<UserSummaryDto>builder()
                .content(userSummaries)
                .page(page)
                .size(size)
                .totalElements(usersPage.getTotalElements())
                .totalPages(usersPage.getTotalPages())
                .first(usersPage.isFirst())
                .last(usersPage.isLast())
                .hasNext(usersPage.hasNext())
                .hasPrevious(usersPage.hasPrevious())
                .build();
    }

    /**
     * Récupère les détails complets d'un utilisateur (Admin)
     */
    public AdminUserDetailDto getUserDetails(Long userId) {
        User user = utilisateurRepository.findById(userId)
                .orElseThrow(() -> new EntityNotFoundException("Utilisateur non trouvé"));

        // Récupérer les sessions actives
        List<SessionInfo> activeSessions = sessionService.getActiveSessions(user, null);

        // Récupérer les tentatives de connexion récentes
        List<LoginAttemptSummary> recentAttempts = loginAttemptRepository
                .findTop10ByEmailOrderByAttemptTimeDesc(user.getEmail())
                .stream()
                .map(this::mapToLoginAttemptSummary)
                .collect(Collectors.toList());

        return AdminUserDetailDto.builder()
                .id(user.getId())
                .email(user.getEmail())
                .name(dataEncryption.decryptSensitiveData(user.getName()))
                .pname(dataEncryption.decryptSensitiveData(user.getPname()))
                .role(user.getRoles())
                .accountStatus(user.getAccountStatus())
                .emailVerified(user.getEmailVerified())
                .createdAt(user.getCreatedAt())
                .lastLogin(user.getLastSuccessfulLogin())
                .updatedAt(user.getUpdatedAt())
                .failedLoginAttempts(user.getFailedLoginAttempts())
                .isTemporarilyLocked(user.isTemporarilyLocked())
                .lockedUntil(user.getLockedUntil())
                .lastLoginIp(user.getLastLoginIp())
                .createdByAdmin(
                        user.getCreatedByAdmin() != null
                                ? user.getCreatedByAdmin().getName() + "-"
                                + user.getCreatedByAdmin().getUsername() + "-"
                                + user.getCreatedByAdmin().getEmail()
                                : null
                )
                .activeSessions(activeSessions)
                .recentLoginAttempts(recentAttempts)
                .build();
    }

    /**
     * Met à jour le statut d'un utilisateur (Admin)
     */
    @Transactional
    public ResponseDto updateUserStatus(Long userId, UserStatusUpdateRequest request, String adminEmail) {
        User user = utilisateurRepository.findById(userId)
                .orElseThrow(() -> new EntityNotFoundException("Utilisateur non trouvé"));

        AccountStatus oldStatus = user.getAccountStatus();
        user.setAccountStatus(request.getNewStatus());
        user.setUpdatedAt(LocalDateTime.now());

        // Si le compte est déverrouillé, réinitialiser les tentatives
        if (request.getNewStatus() == AccountStatus.ACTIVE && oldStatus == AccountStatus.LOCKED) {
            user.setFailedLoginAttempts(0);
            user.setLockedUntil(null);
        }

        utilisateurRepository.save(user);

        // Audit log
        auditMicroserviceClient.logAuditEvent(
                "USER_STATUS_UPDATED_BY_ADMIN",
                user.getEmail(),
                String.format("Statut changé de %s à %s par %s. Raison: %s",
                        oldStatus, request.getNewStatus(), adminEmail, request.getReason()),
                getCurrentHttpRequest(),
                0L
        );

        // Notification à l'utilisateur si demandée
        if (request.getSendNotification()) {
            sendStatusChangeNotification(user, oldStatus, request.getNewStatus(), request.getReason());
        }

        return ResponseDto.builder()
                .success(true)
                .message("Statut utilisateur mis à jour avec succès")
                .build();
    }

    /**
     * Méthodes utilitaires de mapping
     */
    private UserSummaryDto mapToUserSummary(User user) {
        return UserSummaryDto.builder()
                .id(user.getId())
                .email(user.getEmail())
                .name(dataEncryption.decryptSensitiveData(user.getName()))
                .pname(dataEncryption.decryptSensitiveData(user.getPname()))
                .role(user.getRoles())
                .accountStatus(user.getAccountStatus())
                .emailVerified(user.getEmailVerified())
                .createdAt(user.getCreatedAt())
                .lastLogin(user.getLastSuccessfulLogin())
                .failedLoginAttempts(user.getFailedLoginAttempts())
                .isTemporarilyLocked(user.isTemporarilyLocked())
                .build();
    }

    private LoginAttemptSummary mapToLoginAttemptSummary(LoginAttempt attempt) {
        return LoginAttemptSummary.builder()
                .ipAddress(attempt.getIpAddress())
                .success(attempt.getSuccess())
                .failureReason(attempt.getFailureReason())
                .attemptTime(attempt.getAttemptTime())
                .userAgent(attempt.getUserAgent())
                .build();
    }

    private void sendStatusChangeNotification(User user, AccountStatus oldStatus, AccountStatus newStatus, String reason) {
        try {
            String decryptedName = dataEncryption.decryptSensitiveData(user.getName());
            notificationClient.sendAccountStatusChangeNotification(
                    user.getEmail(),
                    decryptedName,
                    oldStatus.toString(),
                    newStatus.toString(),
                    reason
            );
        } catch (Exception e) {
            log.error("Erreur envoi notification changement statut pour: {}", user.getEmail(), e);
        }
    }

    /**
     * Récupère l'utilisateur actuellement connecté depuis le contexte de sécurité Spring
     * Cette méthode utilise le SecurityContext pour obtenir les détails de l'utilisateur authentifié
     */
    public User getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            throw new IllegalStateException("Aucun utilisateur authentifié trouvé");
        }

        Object principal = authentication.getPrincipal();

        if (principal instanceof User) {
            return (User) principal;
        }

        if (principal instanceof String) {
            // Si le principal est une chaîne (email), charger l'utilisateur depuis la base
            String email = (String) principal;
            return findUserByEmail(email);
        }

        throw new IllegalStateException("Type de principal non supporté: " + principal.getClass());
    }

    /**
     * Extrait l'ID de session depuis le token JWT ou les headers
     * Cette méthode analyse le token JWT pour extraire les claims personnalisés
     * qui contiennent l'identifiant de session
     */
    public String extractSessionIdFromAuth(String authHeader) {
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            try {
                String token = authHeader.substring(7);
                // Essayer d'extraire l'ID de session depuis les claims du JWT
                String sessionId = jwtService.extractClaim(token, claims -> (String) claims.get("sessionId"));

                if (sessionId != null) {
                    return sessionId;
                }

                // Fallback: générer un ID basé sur le token pour retrouver la session
                String userEmail = jwtService.extractuserEmail(token);
                return "session-" + userEmail.hashCode() + "-" + token.substring(token.length() - 10);

            } catch (Exception e) {
                log.warn("Impossible d'extraire l'ID de session du token: {}", e.getMessage());
            }
        }
        return "unknown-session-" + System.currentTimeMillis();
    }

    public String extractClientIp(HttpServletRequest httpRequest){
        String ip = httpRequest.getHeader("X-Forwarded-For");
        //return ip == null ? ip: httpRequest.getRemoteAddr();

        if (ip == null || ip.isBlank() || "unknown".equalsIgnoreCase(ip)) {
            ip = httpRequest.getHeader("Proxy-Client-IP");
        }
        if (ip == null || ip.isBlank() || "unknown".equalsIgnoreCase(ip)) {
            ip = httpRequest.getHeader("WL-Proxy-Client-IP");
        }
        if (ip == null || ip.isBlank() || "unknown".equalsIgnoreCase(ip)) {
            ip = httpRequest.getRemoteAddr();
        }
        return ip;
    }
}
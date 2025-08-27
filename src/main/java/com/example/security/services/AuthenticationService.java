package com.example.security.services;

import com.example.security.configuraton.JwtService;
import com.example.security.constants.AccountStatus;
import com.example.security.constants.TypeRoles;
import com.example.security.dto.*;
import com.example.security.entites.User;
import com.example.security.module.notifications.NotificationClient;
import com.example.security.outils.DataEncryption;
import com.example.security.repositories.UserRepository;
import com.example.security.module.auditsLogs.AuditMicroserviceClient;
import jakarta.persistence.EntityNotFoundException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Service
@Slf4j
public class AuthenticationService {

    @Value("${jwt.expiration}")
    private String jwtExpiration;

    @Value("${jwt.token-type}")
    private String tokenType;

    @Value("${email.verification.expiration:24}")
    private int emailVerificationExpirationHours;

    private final UserRepository utilisateurRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final AuditMicroserviceClient auditMicroserviceClient;
    private final NotificationClient notificationClient;
    private final DataEncryption dataEncryption;

    @Autowired
    public AuthenticationService(UserRepository utilisateurRepository, PasswordEncoder passwordEncoder, JwtService jwtService, AuthenticationManager authenticationManager, AuditMicroserviceClient auditMicroserviceClient, NotificationClient notificationClient, DataEncryption dataEncryption) {
        this.utilisateurRepository = utilisateurRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
        this.auditMicroserviceClient = auditMicroserviceClient;
        this.notificationClient = notificationClient;
        this.dataEncryption = dataEncryption;
    }

    /**
     * Étape 1: Inscription avec envoi d'email de vérification
     */
    public RegisterResponse register(RegisterRequest request) {
        long startTime = System.currentTimeMillis();
        HttpServletRequest httpRequest = getCurrentHttpRequest();

        try {
            // Vérifier si l'email existe déjà
            if (utilisateurRepository.findByEmail(request.getEmail()).isPresent()) {
                throw new IllegalArgumentException("Un compte avec cet email existe déjà");
            }

            // Générer le token de vérification
            String verificationToken = generateVerificationToken();
            log.info("putte  "+verificationToken);
            LocalDateTime expiresAt = LocalDateTime.now().plusHours(emailVerificationExpirationHours);

            // Créer l'utilisateur en attente de vérification
            var user = User.builder()
                    .name(dataEncryption.encryptSensitiveData(request.getName()))
                    .pname(dataEncryption.encryptSensitiveData(request.getPname()))
                    .email(request.getEmail())
                    .passwd(passwordEncoder.encode(request.getPasswd()))
                    .roles(TypeRoles.USER)
                    .emailVerified(false)
                    .emailVerificationToken(verificationToken)
                    .emailVerificationExpiresAt(expiresAt)
                    .accountStatus(AccountStatus.PENDING_VERIFICATION)
                    .build();

            utilisateurRepository.save(user);

            // Envoyer l'email de vérification
            notificationClient.sendEmailVerification(
                    request.getEmail(),
                    request.getName(),
                    verificationToken
            );

            // AUDIT
            long executionTime = System.currentTimeMillis() - startTime;
            auditMicroserviceClient.logAuditEvent(
                    "USER_REGISTRATION_PENDING",
                    request.getEmail(),
                    "Inscription en attente de vérification email",
                    httpRequest,
                    executionTime
            );

            log.info("✅ Utilisateur créé en attente de vérification: {}", request.getEmail());

            return RegisterResponse.builder()
                    .message("Inscription réussie! Veuillez vérifier votre email pour activer votre compte.")
                    .emailSent(true)
                    .verificationRequired(true)
                    .build();

        } catch (Exception e) {
            long executionTime = System.currentTimeMillis() - startTime;
            auditMicroserviceClient.logAuditEvent(
                    "USER_REGISTRATION_FAILED",
                    request.getEmail(),
                    "Échec d'enregistrement: " + e.getMessage(),
                    httpRequest,
                    executionTime
            );

            log.error("❌ Échec d'enregistrement pour: {}", request.getEmail(), e);
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

        log.info("🔑 Tentative de connexion pour: {}", request.getEmail());

        try {
            User user = (User) utilisateurRepository.findByEmail(request.getEmail())
                    .orElseThrow(() -> {
                        auditMicroserviceClient.logSecurityEvent(
                                "LOGIN_ATTEMPT_UNKNOWN_USER",
                                request.getEmail(),
                                "MEDIUM",
                                "Tentative de connexion avec email inexistant",
                                httpRequest
                        );
                        return new EntityNotFoundException("Utilisateur non trouvé");
                    });

            // Vérifier si l'email est vérifié
            if (!user.getEmailVerified()) {
                auditMicroserviceClient.logSecurityEvent(
                        "LOGIN_ATTEMPT_UNVERIFIED_EMAIL",
                        request.getEmail(),
                        "MEDIUM",
                        "Tentative de connexion avec email non vérifié",
                        httpRequest
                );
                throw new IllegalArgumentException("Veuillez d'abord vérifier votre email");
            }

            // Vérifier le statut du compte
            if (user.getAccountStatus() != AccountStatus.ACTIVE) {
                auditMicroserviceClient.logSecurityEvent(
                        "LOGIN_ATTEMPT_INACTIVE_ACCOUNT",
                        request.getEmail(),
                        "HIGH",
                        "Tentative de connexion avec compte inactif: " + user.getAccountStatus(),
                        httpRequest
                );
                throw new IllegalArgumentException("Compte inactif ou suspendu");
            }

            if (passwordEncoder.matches(request.getPassword(), user.getPassword())) {
                String jwtToken = jwtService.generateToken(user);
                String refreshToken = jwtService.generateRefreshToken(user);

                // AUDIT DE SUCCÈS
                long executionTime = System.currentTimeMillis() - startTime;
                auditMicroserviceClient.logAuditEvent(
                        "USER_LOGIN_SUCCESS",
                        request.getEmail(),
                        "Connexion réussie",
                        httpRequest,
                        executionTime
                );

                log.info("✅ Connexion réussie pour: {}", request.getEmail());

                return RefreshTokenRequest.AuthenticationResponse.builder()
                        .token(jwtToken)
                        .refreshToken(refreshToken)
                        .expiresIn(Long.valueOf(jwtExpiration))
                        .tokenType(tokenType)
                        .build();
            } else {
                auditMicroserviceClient.logSecurityEvent(
                        "LOGIN_FAILED_WRONG_PASSWORD",
                        request.getEmail(),
                        "HIGH",
                        "Tentative de connexion avec mot de passe incorrect",
                        httpRequest
                );

                log.warn("❌ Mot de passe incorrect pour: {}", request.getEmail());
                throw new EntityNotFoundException("Identifiants invalides");
            }
        } catch (Exception e) {
            long executionTime = System.currentTimeMillis() - startTime;
            auditMicroserviceClient.logAuditEvent(
                    "USER_LOGIN_ERROR",
                    request.getEmail(),
                    "Erreur lors de l'authentification: " + e.getMessage(),
                    httpRequest,
                    executionTime
            );

            log.error("💥 Erreur d'authentification pour: {}", request.getEmail(), e);
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

    public void logout(String authHeader) {
        HttpServletRequest httpRequest = getCurrentHttpRequest();

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);

            try {
                String userEmail = jwtService.extractuserEmail(token);
                jwtService.blacklistToken(token);

                // AUDIT DE DÉCONNEXION
                auditMicroserviceClient.logAuditEvent(
                        "USER_LOGOUT_SUCCESS",
                        userEmail,
                        "Déconnexion réussie, token blacklisté",
                        httpRequest,
                        0L
                );

                log.info("👋 Utilisateur déconnecté: {}", userEmail);

            } catch (Exception e) {
                auditMicroserviceClient.logSecurityEvent(
                        "LOGOUT_ERROR",
                        "unknown",
                        "MEDIUM",
                        "Erreur lors de la déconnexion: " + e.getMessage(),
                        httpRequest
                );
                throw e;
            }
        } else {
            auditMicroserviceClient.logSecurityEvent(
                    "LOGOUT_INVALID_TOKEN",
                    "unknown",
                    "MEDIUM",
                    "Tentative de déconnexion avec token invalide",
                    httpRequest
            );

            log.warn("⚠️ Tentative de logout avec header Authorization invalide");
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
}
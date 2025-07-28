package com.example.security.auth;

import com.example.security.configuraton.JwtService;
import com.example.security.constants.TypeRoles;
import com.example.security.entites.User;
import com.example.security.logs.AuditService;
import com.example.security.repositories.UserRepository;
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

@Service
@Slf4j
public class AuthenticationService {

    @Value("${jwt.expiration}")
    private String jwtExpiration;

    @Value("${jwt.token-type}")
    private String tokenType;

    private final UserRepository utilisateurRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final AuditService auditService;

    @Autowired
    public AuthenticationService(UserRepository utilisateurRepository, PasswordEncoder passwordEncoder, JwtService jwtService, AuthenticationManager authenticationManager, AuditService auditService) {
        this.utilisateurRepository = utilisateurRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
        this.auditService = auditService;
    }

    public AuthenticationResponse register(RegisterRequest request) {
        long startTime = System.currentTimeMillis();
        HttpServletRequest httpRequest = getCurrentHttpRequest();

        try {
            var user = User.builder()
                    .name(request.getName())
                    .pname(request.getPname())
                    .email(request.getEmail())
                    .passwd(passwordEncoder.encode(request.getPasswd()))
                    .roles(TypeRoles.USER)
                    .build();

            utilisateurRepository.save(user);
            var refreshToken = jwtService.generateRefreshToken(user);
            var jwtToken = jwtService.generateToken(user);

            // AUDIT
            long executionTime = System.currentTimeMillis() - startTime;
            auditService.logAuditEvent(
                    "USER_REGISTRATION_SUCCESS",
                    request.getEmail(),
                    "Nouveau utilisateur enregistré avec succès",
                    httpRequest,
                    executionTime
            );

            log.info("✅ Utilisateur enregistré avec succès: {}", request.getEmail());

            return AuthenticationResponse.builder()
                    .token(jwtToken)
                    .refreshToken(refreshToken)
                    .expiresIn(Long.valueOf(jwtExpiration))
                    .tokenType(tokenType)
                    .build();

        } catch (Exception e) {

            long executionTime = System.currentTimeMillis() - startTime;
            auditService.logAuditEvent(
                    "USER_REGISTRATION_FAILED",
                    request.getEmail(),
                    "Échec d'enregistrement: " + e.getMessage(),
                    httpRequest,
                    executionTime
            );

            auditService.logSecurityEvent(
                    "REGISTRATION_FAILED",
                    request.getEmail(),
                    "MEDIUM",
                    "Tentative d'enregistrement échouée: " + e.getMessage(),
                    httpRequest
            );

            log.error("❌ Échec d'enregistrement pour: {}", request.getEmail(), e);
            throw e;
        }
    }

    public AuthenticationResponse registerAdmin(RegisterRequest request) {
        long startTime = System.currentTimeMillis();
        HttpServletRequest httpRequest = getCurrentHttpRequest();

        try {
            var user = User.builder()
                    .name(request.getName())
                    .pname(request.getPname())
                    .email(request.getEmail())
                    .passwd(passwordEncoder.encode(request.getPasswd()))
                    .roles(TypeRoles.ADMIN)
                    .build();

            utilisateurRepository.save(user);
            var refreshToken = jwtService.generateRefreshToken(user);
            var jwtToken = jwtService.generateToken(user);

            // AUDIT CRITIQUE POUR ADMIN
            long executionTime = System.currentTimeMillis() - startTime;
            auditService.logAuditEvent(
                    "ADMIN_REGISTRATION_SUCCESS",
                    request.getEmail(),
                    "Nouvel administrateur enregistré",
                    httpRequest,
                    executionTime
            );

            auditService.logSecurityEvent(
                    "ADMIN_ACCOUNT_CREATED",
                    request.getEmail(),
                    "HIGH",
                    "Création d'un compte administrateur",
                    httpRequest
            );

            log.warn("🔐 Administrateur créé: {}", request.getEmail());

            return AuthenticationResponse.builder()
                    .token(jwtToken)
                    .refreshToken(refreshToken)
                    .expiresIn(Long.valueOf(jwtExpiration))
                    .tokenType(tokenType)
                    .build();

        } catch (Exception e) {
            long executionTime = System.currentTimeMillis() - startTime;
            auditService.logSecurityEvent(
                    "ADMIN_REGISTRATION_FAILED",
                    request.getEmail(),
                    "CRITICAL",
                    "Tentative de création d'admin échouée: " + e.getMessage(),
                    httpRequest
            );
            throw e;
        }
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        long startTime = System.currentTimeMillis();
        HttpServletRequest httpRequest = getCurrentHttpRequest();

        log.info("🔑 Tentative de connexion pour: {}", request.getEmail());

        try {
            UserDetails user = utilisateurRepository.findByEmail(request.getEmail())
                    .orElseThrow(() -> {
                        // AUDIT D'ÉCHEC - Utilisateur inexistant
                        auditService.logSecurityEvent(
                                "LOGIN_ATTEMPT_UNKNOWN_USER",
                                request.getEmail(),
                                "MEDIUM",
                                "Tentative de connexion avec email inexistant",
                                httpRequest
                        );
                        return new EntityNotFoundException("Utilisateur non trouvé");
                    });

            if (passwordEncoder.matches(request.getPassword(), user.getPassword())) {
                String jwtToken = jwtService.generateToken(user);
                String refreshToken = jwtService.generateRefreshToken(user);

                // AUDIT DE SUCCÈS
                long executionTime = System.currentTimeMillis() - startTime;
                auditService.logAuditEvent(
                        "USER_LOGIN_SUCCESS",
                        request.getEmail(),
                        "Connexion réussie",
                        httpRequest,
                        executionTime
                );

                log.info("✅ Connexion réussie pour: {}", request.getEmail());

                return AuthenticationResponse.builder()
                        .token(jwtToken)
                        .refreshToken(refreshToken)
                        .expiresIn(Long.valueOf(jwtExpiration))
                        .tokenType(tokenType)
                        .build();
            } else {
                // AUDIT D'ÉCHEC - Mot de passe incorrect
                auditService.logAuditEvent(
                        "USER_LOGIN_FAILED",
                        request.getEmail(),
                        "Mot de passe incorrect",
                        httpRequest,
                        System.currentTimeMillis() - startTime
                );

                auditService.logSecurityEvent(
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
            // AUDIT GÉNÉRAL D'ÉCHEC
            long executionTime = System.currentTimeMillis() - startTime;
            auditService.logAuditEvent(
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

    public AuthenticationResponse refreshToken(RefreshTokenRequest request) {
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
            auditService.logAuditEvent(
                    "TOKEN_REFRESH_SUCCESS",
                    userEmail,
                    "Token rafraîchi avec succès",
                    httpRequest,
                    executionTime
            );

            return AuthenticationResponse.builder()
                    .token(newAccessToken)
                    .refreshToken(refreshToken)
                    .expiresIn(Long.valueOf(jwtExpiration))
                    .tokenType(tokenType)
                    .build();

        } catch (Exception e) {
            auditService.logSecurityEvent(
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
                auditService.logAuditEvent(
                        "USER_LOGOUT_SUCCESS",
                        userEmail,
                        "Déconnexion réussie, token blacklisté",
                        httpRequest,
                        0L
                );

                log.info("👋 Utilisateur déconnecté: {}", userEmail);

            } catch (Exception e) {
                auditService.logSecurityEvent(
                        "LOGOUT_ERROR",
                        "unknown",
                        "MEDIUM",
                        "Erreur lors de la déconnexion: " + e.getMessage(),
                        httpRequest
                );
                throw e;
            }
        } else {
            auditService.logSecurityEvent(
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
    private HttpServletRequest getCurrentHttpRequest() {
        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        return attributes != null ? attributes.getRequest() : null;
    }
}
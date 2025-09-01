package com.example.security.services;

import com.example.security.constants.AccountStatus;
import com.example.security.constants.TypeRoles;
import com.example.security.configuraton.JwtService;
import com.example.security.dto.GoogleUserInfo;
import com.example.security.dto.OAuth2LoginRequest;
import com.example.security.dto.RefreshTokenRequest;
import com.example.security.entites.User;
import com.example.security.module.auditsLogs.AuditMicroserviceClient;
import com.example.security.repositories.UserRepository;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Service
@Slf4j
@RequiredArgsConstructor
public class OAuth2Service {

    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final AuditMicroserviceClient auditMicroserviceClient;
    private final SessionService sessionService;

    @Value("${oauth2.google.client-id}")
    private String googleClientId;

    @Value("${oauth2.google.client-secret}")
    private String googleClientSecret;

    @Value("${jwt.expiration}")
    private String jwtExpiration;

    @Value("${jwt.token-type}")
    private String tokenType;

    private final RestTemplate restTemplate = new RestTemplate();
    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * Connexion/Inscription via Google OAuth2
     */
    public RefreshTokenRequest.AuthenticationResponse authenticateWithGoogle(OAuth2LoginRequest request) throws Exception {
        long startTime = System.currentTimeMillis();
        HttpServletRequest httpRequest = getCurrentHttpRequest();

        try {
            // 1. Valider le token Google et récupérer les infos utilisateur
            GoogleUserInfo googleUserInfo = validateGoogleTokenAndGetUserInfo(request.getGoogleToken());

            // 2. Chercher ou créer l'utilisateur
            User user = findOrCreateGoogleUser(googleUserInfo);

            // 3. Vérifier que le compte est actif
            if (!user.canLogin()) {
                throw new IllegalStateException("Compte inactif ou suspendu");
            }

            // 4. Générer les tokens JWT
            String jwtToken = jwtService.generateToken(user);
            String refreshToken = jwtService.generateRefreshToken(user);

            // 5. Créer une nouvelle session
            sessionService.createSession(user, httpRequest, request.getDeviceInfo());

            // 6. Mettre à jour les informations de dernière connexion
            user.resetFailedLoginAttempts();
            userRepository.save(user);

            // 7. Audit
            long executionTime = System.currentTimeMillis() - startTime;
            auditMicroserviceClient.logAuditEvent(
                    "OAUTH2_LOGIN_SUCCESS",
                    user.getEmail(),
                    "Connexion réussie via Google OAuth2",
                    httpRequest,
                    executionTime
            );

            log.info("✅ Connexion Google réussie pour: {} (Google ID: {})", user.getEmail(), user.getGoogleId());

            return RefreshTokenRequest.AuthenticationResponse.builder()
                    .token(jwtToken)
                    .refreshToken(refreshToken)
                    .expiresIn(Long.valueOf(jwtExpiration))
                    .tokenType(tokenType)
                    .build();

        } catch (Exception e) {
            long executionTime = System.currentTimeMillis() - startTime;
            auditMicroserviceClient.logSecurityEvent(
                    "OAUTH2_LOGIN_FAILED",
                    "unknown",
                    "HIGH",
                    "Échec connexion Google OAuth2: " + e.getMessage(),
                    httpRequest
            );

            log.error("❌ Échec connexion Google OAuth2", e);
            throw e;
        }
    }

    /**
     * Valide le token Google et récupère les informations utilisateur
     */
    private GoogleUserInfo validateGoogleTokenAndGetUserInfo(String googleToken) throws Exception {
        // URL de validation Google
        String validationUrl = "https://www.googleapis.com/oauth2/v3/tokeninfo?id_token=" + googleToken;

        try {
            ResponseEntity<String> response = restTemplate.getForEntity(validationUrl, String.class);

            if (response.getStatusCode() != HttpStatus.OK) {
                throw new IllegalArgumentException("Token Google invalide");
            }

            JsonNode jsonNode = objectMapper.readTree(response.getBody());

            // Vérifier que le token est pour notre application
            String audience = jsonNode.get("aud").asText();
            if (!googleClientId.equals(audience)) {
                throw new IllegalArgumentException("Token Google ne correspond pas à l'application");
            }

            // Extraire les informations utilisateur
            return GoogleUserInfo.builder()
                    .googleId(jsonNode.get("sub").asText())
                    .email(jsonNode.get("email").asText())
                    .emailVerified(jsonNode.get("email_verified").asBoolean())
                    .name(jsonNode.get("given_name").asText())
                    .familyName(jsonNode.get("family_name").asText())
                    .picture(jsonNode.has("picture") ? jsonNode.get("picture").asText() : null)
                    .build();

        } catch (Exception e) {
            log.error("❌ Erreur validation token Google: {}", e.getMessage());
            throw new IllegalArgumentException("Token Google invalide ou expiré");
        }
    }

    /**
     * Trouve un utilisateur existant ou crée un nouveau compte Google
     */
    private User findOrCreateGoogleUser(GoogleUserInfo googleUserInfo) {
        // Chercher d'abord par Google ID
        Optional<User> existingByGoogleId = userRepository.findByGoogleId(googleUserInfo.getGoogleId());
        if (existingByGoogleId.isPresent()) {
            User user = existingByGoogleId.get();
            updateUserProfileFromGoogle(user, googleUserInfo);
            return user;
        }

        // Chercher par email
        Optional<User> existingByEmail = userRepository.findByEmail(googleUserInfo.getEmail());
        if (existingByEmail.isPresent()) {
            User user = existingByEmail.get();

            // Lier le compte Google existant
            if (user.getGoogleId() == null) {
                user.setGoogleId(googleUserInfo.getGoogleId());
                user.setProfilePictureUrl(googleUserInfo.getPicture());
                user.setRegistrationMethod("EMAIL_THEN_GOOGLE");

                // Si l'email n'était pas vérifié et que Google le confirme
                if (!user.getEmailVerified() && googleUserInfo.isEmailVerified()) {
                    user.setEmailVerified(true);
                    user.setAccountStatus(AccountStatus.ACTIVE);
                    user.setEmailVerificationToken(null);
                    user.setEmailVerificationExpiresAt(null);
                }

                userRepository.save(user);

                auditMicroserviceClient.logAuditEvent(
                        "GOOGLE_ACCOUNT_LINKED",
                        user.getEmail(),
                        "Compte existant lié à Google",
                        getCurrentHttpRequest(),
                        0L
                );

                log.info("🔗 Compte existant lié à Google: {}", user.getEmail());
            }

            return user;
        }

        // Créer un nouveau compte Google
        User newUser = User.builder()
                .name(googleUserInfo.getName())
                .pname(googleUserInfo.getFamilyName())
                .email(googleUserInfo.getEmail())
                .passwd("") // Pas de mot de passe pour les comptes Google
                .roles(TypeRoles.USER)
                .emailVerified(googleUserInfo.isEmailVerified())
                .accountStatus(googleUserInfo.isEmailVerified() ? AccountStatus.ACTIVE : AccountStatus.PENDING_VERIFICATION)
                .googleId(googleUserInfo.getGoogleId())
                .registrationMethod("GOOGLE")
                .profilePictureUrl(googleUserInfo.getPicture())
                .build();

        userRepository.save(newUser);

        auditMicroserviceClient.logAuditEvent(
                "GOOGLE_ACCOUNT_CREATED",
                newUser.getEmail(),
                "Nouveau compte créé via Google OAuth2",
                getCurrentHttpRequest(),
                0L
        );

        log.info("✨ Nouveau compte Google créé: {}", newUser.getEmail());
        return newUser;
    }

    /**
     * Met à jour les informations du profil depuis Google
     */
    private void updateUserProfileFromGoogle(User user, GoogleUserInfo googleUserInfo) {
        boolean updated = false;

        if (googleUserInfo.getPicture() != null &&
                !googleUserInfo.getPicture().equals(user.getProfilePictureUrl())) {
            user.setProfilePictureUrl(googleUserInfo.getPicture());
            updated = true;
        }

        if (!user.getEmailVerified() && googleUserInfo.isEmailVerified()) {
            user.setEmailVerified(true);
            user.setAccountStatus(AccountStatus.ACTIVE);
            user.setEmailVerificationToken(null);
            user.setEmailVerificationExpiresAt(null);
            updated = true;
        }

        if (updated) {
            userRepository.save(user);
            log.debug("👤 Profil utilisateur mis à jour depuis Google: {}", user.getEmail());
        }
    }

    private HttpServletRequest getCurrentHttpRequest() {
        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        return attributes != null ? attributes.getRequest() : null;
    }
}
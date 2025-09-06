package com.example.security.module.notifications;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

@Component
@Slf4j
public class NotificationClient {

    @Value("${notification.service.url:http://localhost:9001}")
    private String notificationServiceUrl;

    @Value("${frontend.base.url:http://localhost:9001}")
    private String frontendbase;

    private final RestTemplate restTemplate;

    public NotificationClient() {
        this.restTemplate = new RestTemplate();
    }

    public ResponseEntity<String> send(NotificationRequestDto request) {
        try{
            String url = notificationServiceUrl + "/api/notifications/send";

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            HttpEntity<NotificationRequestDto> entity = new HttpEntity<>(request, headers);

            ResponseEntity<String> response = restTemplate.postForEntity(url, entity, String.class);;

            log.info("✅ Email envoyé à: {}", request.recipientEmail);
            return response;
        }catch (Exception e) {
            log.error("❌ Erreur lors de l'envoi de l'email pour: {}",  request.recipientEmail, e);
            // Ne pas faire échouer l'inscription à cause d'un problème d'email
            // mais logger l'erreur pour investigation
        }
        return null;
    }

    /**
     * Envoie un email de vérification
     */
    public void sendEmailVerification(String email, String name, String verificationToken) {

        NotificationRequestDto request = NotificationRequestDto.builder()
                .title("Vérification de votre adresse email")
                .type(NotificationType.SECURITY)
                .priority(NotificationPriority.HIGH)
                .recipientId(email)
                .recipientEmail(email)
                .channels(Set.of(ChannelType.EMAIL))
                .templateId("email_verification")
                .parameters(Map.of(
                        "name", name,
                        "verificationToken", verificationToken,
                        "verificationUrl", generateVerificationUrl(verificationToken)
                ))
                .build();

        ResponseEntity<String> response = send(request);

        log.info("response: {}", response.getBody());
        if  (response == null) log.error("❌ Erreur lors de l'envoi de l'email de vérification pour: {}", email);

        if (response.getStatusCode().is2xxSuccessful()) {
            log.info("✅ Email de vérification envoyé avec succès à: {}", email);
        } else {
            log.warn("⚠️ Réponse inattendue du service de notification: {}", response.getStatusCode());

        }

    }

    /**
     * Envoie un email de bienvenue après vérification
     */
    public void sendWelcomeEmail(String email, String name) {

        NotificationRequestDto request = NotificationRequestDto.builder()
                .title("Bienvenue sur notre plateforme !")
                .type(NotificationType.WELCOME)
                .priority(NotificationPriority.MEDIUM)
                .recipientId(email)
                .recipientEmail(email)
                .channels(Set.of(ChannelType.EMAIL))
                .templateId("welcome_email")
                .parameters(Map.of(
                        "name", name,
                        "loginUrl", generateLoginUrl()
                ))
                .build();

        ResponseEntity<String> response = send(request);

        if(response == null) log.error("❌ Erreur lors de l'envoi de l'email de bienvenue pour: {}", email);
        if (response.getStatusCode().is2xxSuccessful()) {
            log.info("✅ Email de Bienvenue envoyé avec succès à: {}", email);
        } else {
            log.warn("⚠️ Réponse inattendue du service de notification: {}", response.getStatusCode());

        }

    }

    /**
     * Notification de verrouillage de compte
     */
    public void sendAccountLockedNotification(String email, String name, int lockoutDurationMinutes) {
        try {
            NotificationRequestDto request = NotificationRequestDto.builder()
                    .title("Votre compte a été temporairement verrouillé")
                    .type(NotificationType.SECURITY)
                    .priority(NotificationPriority.HIGH)
                    .recipientId(email)
                    .recipientEmail(email)
                    .channels(Set.of(ChannelType.EMAIL, ChannelType.SMS)) // Email + SMS pour sécurité
                    .templateId("account_locked")
                    .parameters(Map.of(
                            "name", name,
                            "lockoutDuration", String.valueOf(lockoutDurationMinutes)
                    ))
                    .build();

            ResponseEntity<String> response = send(request);

            if (response != null && response.getStatusCode().is2xxSuccessful()) {
                log.info("✅ Notification de verrouillage envoyée avec succès à: {} (durée: {}min)",
                        email, lockoutDurationMinutes);
            } else {
                log.warn("⚠️ Réponse inattendue pour notification de verrouillage: {}",
                        response != null ? response.getStatusCode() : "null");
            }

        } catch (Exception e) {
            log.error("❌ Erreur lors de l'envoi de la notification de verrouillage pour: {}", email, e);
        }
    }

    /**
     * Notification de déverrouillage de compte (manuel par admin)
     */
    public void sendAccountUnlockedNotification(String email, String name, String adminEmail) {
        try {
            NotificationRequestDto request = NotificationRequestDto.builder()
                    .title("Votre compte a été déverrouillé")
                    .type(NotificationType.SECURITY)
                    .priority(NotificationPriority.MEDIUM)
                    .recipientId(email)
                    .recipientEmail(email)
                    .channels(Set.of(ChannelType.EMAIL))
                    .templateId("account_unlocked")
                    .parameters(Map.of(
                            "name", name,
                            "adminEmail", adminEmail,
                            "loginUrl", generateLoginUrl()
                    ))
                    .build();

            ResponseEntity<String> response = send(request);

            if (response != null && response.getStatusCode().is2xxSuccessful()) {
                log.info("✅ Notification de déverrouillage envoyée avec succès à: {} par admin: {}",
                        email, adminEmail);
            } else {
                log.warn("⚠️ Réponse inattendue pour notification de déverrouillage: {}",
                        response != null ? response.getStatusCode() : "null");
            }

        } catch (Exception e) {
            log.error("❌ Erreur lors de l'envoi de la notification de déverrouillage pour: {}", email, e);
        }
    }

    /**
     * Notification de changement de statut du compte
     */
    public void sendAccountStatusChangeNotification(String email, String name,String oldStatus, String newStatus, String reason) {
        try {
            NotificationRequestDto request = NotificationRequestDto.builder()
                    .title("Modification du statut de votre compte")
                    .type(NotificationType.SECURITY)
                    .priority(NotificationPriority.MEDIUM)
                    .recipientId(email)
                    .recipientEmail(email)
                    .channels(Set.of(ChannelType.EMAIL))
                    .templateId("account_status_change")
                    .parameters(Map.of(
                            "name", name,
                            "oldStatus", oldStatus,
                            "newStatus", newStatus,
                            "reason", reason != null ? reason : "Non spécifiée"
                    ))
                    .build();

            ResponseEntity<String> response = send(request);

            if (response != null && response.getStatusCode().is2xxSuccessful()) {
                log.info("✅ Notification changement de statut envoyée à: {} ({} -> {})",
                        email, oldStatus, newStatus);
            } else {
                log.warn("⚠️ Réponse inattendue pour changement de statut: {}",
                        response != null ? response.getStatusCode() : "null");
            }

        } catch (Exception e) {
            log.error("❌ Erreur lors de l'envoi de la notification de changement de statut pour: {}", email, e);
        }
    }

    /**
     * Email à l'ancienne adresse lors d'une demande de changement d'email
     */
    public void sendEmailChangeRequestToOldEmail(String oldEmail, String name, String newEmail) {
        try {
            NotificationRequestDto request = NotificationRequestDto.builder()
                    .title("Demande de changement d'adresse email")
                    .type(NotificationType.SECURITY)
                    .priority(NotificationPriority.HIGH)
                    .recipientId(oldEmail)
                    .recipientEmail(oldEmail)
                    .channels(Set.of(ChannelType.EMAIL))
                    .templateId("email_change_request_old")
                    .parameters(Map.of(
                            "name", name,
                            "newEmail", newEmail
                    ))
                    .build();

            ResponseEntity<String> response = send(request);

            if (response != null && response.getStatusCode().is2xxSuccessful()) {
                log.info("✅ Notification demande changement email envoyée à l'ancienne adresse: {}", oldEmail);
            } else {
                log.warn("⚠️ Réponse inattendue pour demande changement email: {}",
                        response != null ? response.getStatusCode() : "null");
            }

        } catch (Exception e) {
            log.error("❌ Erreur lors de l'envoi de la notification à l'ancienne adresse: {}", oldEmail, e);
        }
    }

    /**
     * Email de confirmation à la nouvelle adresse pour changement d'email
     */
    public void sendEmailChangeConfirmationToNewEmail(String newEmail, String name, String confirmationToken) {
        try {
            NotificationRequestDto request = NotificationRequestDto.builder()
                    .title("Confirmez votre nouvelle adresse email")
                    .type(NotificationType.SECURITY)
                    .priority(NotificationPriority.HIGH)
                    .recipientId(newEmail)
                    .recipientEmail(newEmail)
                    .channels(Set.of(ChannelType.EMAIL))
                    .templateId("email_change_confirmation_new")
                    .parameters(Map.of(
                            "name", name,
                            "confirmationToken", confirmationToken,
                            "confirmationUrl", generateEmailChangeConfirmationUrl(confirmationToken)
                    ))
                    .build();

            ResponseEntity<String> response = send(request);

            if (response != null && response.getStatusCode().is2xxSuccessful()) {
                log.info("✅ Email de confirmation changement envoyé à la nouvelle adresse: {}", newEmail);
            } else {
                log.warn("⚠️ Réponse inattendue pour confirmation changement email: {}",
                        response != null ? response.getStatusCode() : "null");
            }

        } catch (Exception e) {
            log.error("❌ Erreur lors de l'envoi de la confirmation à la nouvelle adresse: {}", newEmail, e);
        }
    }

    public void sendEmailChangeCompleteNotifications(String oldEmail, String newEmail) {
        // Notification à l'ancienne adresse
        sendEmailChangeCompleteToOldEmail(oldEmail);

        // Notification à la nouvelle adresse
        sendEmailChangeCompleteToNewEmail(newEmail);
    }

    private void sendEmailChangeCompleteToOldEmail(String oldEmail) {
        try {
            NotificationRequestDto request = NotificationRequestDto.builder()
                    .title("Votre adresse email a été modifiée")
                    .type(NotificationType.SECURITY)
                    .priority(NotificationPriority.MEDIUM)
                    .recipientId(oldEmail)
                    .recipientEmail(oldEmail)
                    .channels(Set.of(ChannelType.EMAIL))
                    .templateId("email_change_complete_old")
                    .parameters(Map.of()) // Pas de paramètres variables
                    .build();

            ResponseEntity<String> response = send(request);

            if (response != null && response.getStatusCode().is2xxSuccessful()) {
                log.info("✅ Notification fin changement envoyée à l'ancienne adresse: {}", oldEmail);
            } else {
                log.warn("⚠️ Réponse inattendue pour notification fin changement (ancienne): {}",
                        response != null ? response.getStatusCode() : "null");
            }

        } catch (Exception e) {
            log.error("❌ Erreur notification fin changement à l'ancienne adresse: {}", oldEmail, e);
        }
    }

    private void sendEmailChangeCompleteToNewEmail(String newEmail) {
        try {
            NotificationRequestDto request = NotificationRequestDto.builder()
                    .title("Bienvenue ! Votre email a été mis à jour")
                    .type(NotificationType.SECURITY)
                    .priority(NotificationPriority.MEDIUM)
                    .recipientId(newEmail)
                    .recipientEmail(newEmail)
                    .channels(Set.of(ChannelType.EMAIL))
                    .templateId("email_change_complete_new")
                    .parameters(Map.of(
                            "loginUrl", generateLoginUrl()
                    ))
                    .build();

            ResponseEntity<String> response = send(request);

            if (response != null && response.getStatusCode().is2xxSuccessful()) {
                log.info("✅ Notification fin changement envoyée à la nouvelle adresse: {}", newEmail);
            } else {
                log.warn("⚠️ Réponse inattendue pour notification fin changement (nouvelle): {}",
                        response != null ? response.getStatusCode() : "null");
            }

        } catch (Exception e) {
            log.error("❌ Erreur notification fin changement à la nouvelle adresse: {}", newEmail, e);
        }
    }

    /**
     * Alerte de sécurité avant verrouillage
     */
    public void sendSecurityWarning(String email, String name, Map<String, String> parameters) {
        try {
            NotificationRequestDto request = NotificationRequestDto.builder()
                    .title("Alerte sécurité - Tentatives multiples")
                    .type(NotificationType.SECURITY)
                    .priority(NotificationPriority.HIGH)
                    .recipientId(email)
                    .recipientEmail(email)
                    .channels(Set.of(ChannelType.EMAIL, ChannelType.SMS))
                    .templateId("security_warning")
                    .parameters(
                            new HashMap<String, String>() {{
                                put("name", name);
                                putAll(parameters);
                            }}
                    )
                    .build();

            ResponseEntity<String> response = send(request);

            if (response != null && response.getStatusCode().is2xxSuccessful()) {
                log.info("✅ Alerte de sécurité envoyée avec succès à: {}", email);
            } else {
                log.warn("⚠️ Réponse inattendue pour alerte de sécurité: {}",
                        response != null ? response.getStatusCode() : "null");
            }

        } catch (Exception e) {
            log.error("❌ Erreur lors de l'envoi de l'alerte de sécurité pour: {}", email, e);
        }
    }

    /**
     * Notification d'activité suspecte
     */
    public void sendSuspiciousActivityNotification(String email, String name, Map<String, String> parameters) {
        try {
            NotificationRequestDto request = NotificationRequestDto.builder()
                    .title("Activité suspecte détectée")
                    .type(NotificationType.SECURITY)
                    .priority(NotificationPriority.HIGH)
                    .recipientId(email)
                    .recipientEmail(email)
                    .channels(Set.of(ChannelType.EMAIL))
                    .templateId("suspicious_activity")
                    .parameters(new HashMap<String, String>() {
                        {
                            put("name", name);
                            put("securityUrl", generateSecurityUrl());
                            putAll(parameters);
                        }}
                    )
                    .build();

            ResponseEntity<String> response = send(request);

            if (response != null && response.getStatusCode().is2xxSuccessful()) {
                log.info("✅ Notification d'activité suspecte envoyée avec succès à: {}", email);
            } else {
                log.warn("⚠️ Réponse inattendue pour notification d'activité suspecte: {}",
                        response != null ? response.getStatusCode() : "null");
            }

        } catch (Exception e) {
            log.error("❌ Erreur lors de l'envoi de la notification d'activité suspecte pour: {}", email, e);
        }
    }

    /**
     * Notification de déverrouillage imminent
     */
    public void sendUnlockSoonNotification(String email, String name, Map<String, String> parameters) {
        try {
            NotificationRequestDto request = NotificationRequestDto.builder()
                    .title("Déverrouillage imminent de votre compte")
                    .type(NotificationType.SECURITY)
                    .priority(NotificationPriority.LOW)
                    .recipientId(email)
                    .recipientEmail(email)
                    .channels(Set.of(ChannelType.EMAIL))
                    .templateId("unlock_soon")
                    .parameters(new HashMap<String, String>() {
                        {
                            put("name", name);
                            putAll(parameters);
                        }}
                    )
                    .build();

            ResponseEntity<String> response = send(request);

            if (response != null && response.getStatusCode().is2xxSuccessful()) {
                log.info("✅ Notification de déverrouillage imminent envoyée avec succès à: {}", email);
            } else {
                log.warn("⚠️ Réponse inattendue pour notification de déverrouillage imminent: {}",
                        response != null ? response.getStatusCode() : "null");
            }

        } catch (Exception e) {
            log.error("❌ Erreur lors de l'envoi de la notification de déverrouillage imminent pour: {}", email, e);
        }
    }

    /**
     * Rapport de sécurité pour les administrateurs
     */
    public void sendSecurityReport(String adminEmail, Map<String, String> stats) {
        try {
            NotificationRequestDto request = NotificationRequestDto.builder()
                    .title("Rapport de sécurité quotidien")
                    .type(NotificationType.SECURITY)
                    .priority(NotificationPriority.MEDIUM)
                    .recipientId(adminEmail)
                    .recipientEmail(adminEmail)
                    .channels(Set.of(ChannelType.EMAIL))
                    .templateId("security_report")
                    .parameters(stats)
                    .build();

            ResponseEntity<String> response = send(request);

            if (response != null && response.getStatusCode().is2xxSuccessful()) {
                log.info("✅ Rapport de sécurité envoyé avec succès à: {}", adminEmail);
            } else {
                log.warn("⚠️ Réponse inattendue pour rapport de sécurité: {}",
                        response != null ? response.getStatusCode() : "null");
            }

        } catch (Exception e) {
            log.error("❌ Erreur lors de l'envoi du rapport de sécurité à: {}", adminEmail, e);
        }
    }

    private String generateVerificationUrl(String token) {
        return String.format("%s/auth/simple/verify-email?token=%s", frontendbase, token);
    }

    private String generateLoginUrl() {
        return String.format("%s/auth/simple/login", frontendbase);
    }

    private String generateEmailChangeConfirmationUrl(String token) {
        return String.format("%s/auth/sessions/confirm-email-change?token=%s", frontendbase, token);
    }

    private String generatePasswordResetUrl(String token) {
        return String.format("%s/auth/simple/reset-password?token=%s", frontendbase, token);
    }

    private String generateSecurityUrl() {
        return String.format("%s/security", frontendbase);
    }

    private String generateDashboardUrl() {
        return String.format("%s/admin/dashboard", frontendbase);
    }

    // DTOs nécessaires (copiées du module notification)
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class NotificationRequestDto {
        private String title;
        private String content;
        private NotificationType type;
        private NotificationPriority priority;
        private String recipientId;
        private String recipientEmail;
        private String recipientPhone;
        private String senderId;
        private Set<ChannelType> channels;
        private LocalDateTime scheduledAt;
        private String templateId;
        private Map<String, String> parameters;
        private String externalId;
        private String metadata;
    }

    // Enums nécessaires
    public enum NotificationType {
        WELCOME, ALERT, REMINDER, PROMOTION, TRANSACTION, SECURITY, SYSTEM, CUSTOM
    }

    public enum NotificationPriority {
        LOW, MEDIUM, HIGH, URGENT
    }

    public enum ChannelType {
        EMAIL, SMS, PUSH, WEB, WEBSOCKET
    }
}




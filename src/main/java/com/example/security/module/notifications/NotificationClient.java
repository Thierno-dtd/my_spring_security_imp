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
import java.util.Map;
import java.util.Set;

@Component
@Slf4j
public class NotificationClient {

    @Value("${notification.service.url:http://localhost:9001}")
    private String notificationServiceUrl;

    private final RestTemplate restTemplate;

    public NotificationClient() {
        this.restTemplate = new RestTemplate();
    }

    /**
     * Envoie un email de vérification
     */
    public void sendEmailVerification(String email, String name, String verificationToken) {
        try {
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

            String url = notificationServiceUrl + "/api/notifications/send";

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            HttpEntity<NotificationRequestDto> entity = new HttpEntity<>(request, headers);

            ResponseEntity<String> response = restTemplate.postForEntity(url, entity, String.class);
            log.info("response: {}", response.getBody());
            if (response.getStatusCode().is2xxSuccessful()) {
                log.info("✅ Email de vérification envoyé avec succès à: {}", email);
            } else {
                log.warn("⚠️ Réponse inattendue du service de notification: {}", response.getStatusCode());
            }

        } catch (Exception e) {
            log.error("❌ Erreur lors de l'envoi de l'email de vérification pour: {}", email, e);
            // Ne pas faire échouer l'inscription à cause d'un problème d'email
            // mais logger l'erreur pour investigation
        }
    }

    /**
     * Envoie un email de bienvenue après vérification
     */
    public void sendWelcomeEmail(String email, String name) {
        try {
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

            String url = notificationServiceUrl + "/api/notifications/send";

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            HttpEntity<NotificationRequestDto> entity = new HttpEntity<>(request, headers);

            restTemplate.postForEntity(url, entity, String.class);

            log.info("✅ Email de bienvenue envoyé à: {}", email);

        } catch (Exception e) {
            log.error("❌ Erreur lors de l'envoi de l'email de bienvenue pour: {}", email, e);
        }
    }

    private String generateVerificationUrl(String token) {
        // À adapter selon votre configuration frontend
        return "http://localhost:3000/verify-email?token=" + token;
    }

    private String generateLoginUrl() {
        return "http://localhost:3000/login";
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




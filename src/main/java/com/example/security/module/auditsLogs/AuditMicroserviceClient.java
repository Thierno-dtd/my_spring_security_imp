package com.example.security.module.auditsLogs;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import jakarta.servlet.http.HttpServletRequest;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@Service
@Slf4j
public class AuditMicroserviceClient {

    @Value("${audit.microservice.url:http://localhost:8080}")
    private String auditServiceUrl;

    private final RestTemplate restTemplate;

    public AuditMicroserviceClient(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    /**
     * Enregistrer un événement d'audit de manière asynchrone
     */
    @Async
    public void logAuditEvent(String eventType, String userEmail, String details,
                              HttpServletRequest request, Long executionTime) {
        try {
            Map<String, Object> auditData = new HashMap<>();
            auditData.put("eventType", eventType);
            auditData.put("userEmail", userEmail);
            auditData.put("details", details);
            auditData.put("ipAddress", extractClientIp(request));
            auditData.put("userAgent", request.getHeader("User-Agent"));
            auditData.put("requestUri", request.getRequestURI());
            auditData.put("httpMethod", request.getMethod());
            auditData.put("executionTime", executionTime);
            auditData.put("timestamp", LocalDateTime.now().toString());

            sendToAuditService("/api/v1/audit/log", auditData);

            log.debug("✅ Événement d'audit envoyé: {}", eventType);

        } catch (Exception e) {
            log.error("❌ Erreur envoi audit vers microservice: {}", e.getMessage());
            // Fallback vers log local
            log.warn("AUDIT_FALLBACK: {} - {} - {}", eventType, userEmail, details);
        }
    }

    /**
     * Enregistrer un événement de sécurité de manière asynchrone
     */
    @Async
    public void logSecurityEvent(String securityEvent, String userEmail, String threatLevel,
                                 String description, HttpServletRequest request) {
        try {
            Map<String, Object> securityData = new HashMap<>();
            securityData.put("securityEvent", securityEvent);
            securityData.put("userEmail", userEmail);
            securityData.put("threatLevel", threatLevel);
            securityData.put("description", description);
            securityData.put("ipAddress", extractClientIp(request));
            securityData.put("timestamp", LocalDateTime.now().toString());

            sendToAuditService("/api/v1/audit/security", securityData);

            log.debug("✅ Événement de sécurité envoyé: {}", securityEvent);

        } catch (Exception e) {
            log.error("❌ Erreur envoi sécurité vers microservice: {}", e.getMessage());
            // Fallback vers log local
            log.error("SECURITY_FALLBACK: {} - {} - {} - {}", securityEvent, userEmail, threatLevel, description);
        }
    }

    /**
     * Méthodes pratiques pour logs fréquents
     */
    public void logUserAction(String action, String userEmail, HttpServletRequest request) {
        logAuditEvent("USER_ACTION", userEmail, action, request, null);
    }

    public void logAuthenticationAttempt(String result, String userEmail, HttpServletRequest request) {
        String eventType = "USER_LOGIN_" + result.toUpperCase();
        String details = "Tentative de connexion: " + result;

        logAuditEvent(eventType, userEmail, details, request, null);

        // Si échec, log aussi en sécurité
        if ("FAILED".equals(result.toUpperCase())) {
            logSecurityEvent("LOGIN_FAILURE", userEmail, "MEDIUM",
                    "Échec de connexion", request);
        }
    }

    public void logRegistration(String result, String userEmail, HttpServletRequest request) {
        String eventType = "USER_REGISTRATION_" + result.toUpperCase();
        String details = "Enregistrement utilisateur: " + result;

        logAuditEvent(eventType, userEmail, details, request, null);
    }

    public void logAdminAction(String action, String userEmail, HttpServletRequest request) {
        logAuditEvent("ADMIN_ACTION", userEmail, action, request, null);

        // Les actions admin sont toujours des événements de sécurité
        logSecurityEvent("ADMIN_OPERATION", userEmail, "HIGH",
                "Action administrateur: " + action, request);
    }

    public void logLogout(String userEmail, HttpServletRequest request) {
        logAuditEvent("USER_LOGOUT_SUCCESS", userEmail,
                "Déconnexion réussie", request, null);
    }

    public void logTokenRefresh(String userEmail, HttpServletRequest request) {
        logAuditEvent("TOKEN_REFRESH_SUCCESS", userEmail,
                "Token rafraîchi avec succès", request, null);
    }

    /**
     * Méthodes privées utilitaires
     */
    private void sendToAuditService(String endpoint, Map<String, Object> data) throws Exception {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        // Ajouter API Key si nécessaire
        // headers.set("X-API-Key", "your-api-key");

        HttpEntity<Map<String, Object>> request = new HttpEntity<>(data, headers);

        String url = auditServiceUrl + endpoint;
        restTemplate.postForEntity(url, request, String.class);
    }

    private String extractClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }

        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }

        return request.getRemoteAddr();
    }

    /**
     * Test de connectivité avec le microservice
     */
    public boolean isAuditServiceAvailable() {
        try {
            String url = auditServiceUrl + "/api/v1/audit/health";
            restTemplate.getForEntity(url, String.class);
            return true;
        } catch (Exception e) {
            log.warn("⚠️ Microservice d'audit non disponible: {}", e.getMessage());
            return false;
        }
    }
}
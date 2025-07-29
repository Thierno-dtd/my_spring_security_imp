package com.example.security.logs.services;

import com.example.security.constants.TypeThreatLevel;
import com.example.security.logs.repositories.AuditLogRepository;
import com.example.security.logs.entities.SecurityLog;
import com.example.security.logs.entities.AuditLog;
import com.example.security.logs.repositories.SecurityLogRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Service
@Slf4j
@EnableAsync
@Async("auditTaskExecutor")
public class AuditService {

    @Autowired
    private AuditLogRepository auditLogRepository;

    @Autowired
    private SecurityLogRepository securityLogRepository;

    @Autowired
    private IpAddressService ipAddressService;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Async
    public void logAuditEvent(String eventType, String userEmail, String details,
                              HttpServletRequest request, Long executionTime) {
        try {
            IpAddressService.IpInfo ipInfo = ipAddressService.getDetailedIpInfo(request);
            String sessionId = extractSessionId(request);
            log.error("putea"+ sessionId);

            AuditLog auditLog = AuditLog.builder()
                    .timestamp(LocalDateTime.now())
                    .eventType(eventType)
                    .userEmail(userEmail)
                    .details(details)
                    .ipAddress(ipInfo.getIpAddress())
                    .userAgent(ipInfo.getUserAgent())
                    .requestUri(ipInfo.getRequestUri())
                    .httpMethod(ipInfo.getMethod())
                    .sessionId(sessionId)
                    .sessionId(request.getSession(false) != null ? request.getSession().getId() : null)
                    .executionTime(executionTime)
                    .threatLevel(determineThreatLevel(eventType, ipInfo))
                    .additionalData(createAdditionalData(ipInfo))
                    .build();

            auditLogRepository.save(auditLog);

            log.info("AUDIT: {} - {} - {} | Session: {} | {}",
                    eventType, userEmail, details, sessionId, ipInfo.toString());

        } catch (Exception e) {
            log.error("Erreur sauvegarde audit DB, fallback vers fichier", e);
            log.warn("AUDIT_FALLBACK: {} - {} - {}", eventType, userEmail, details);
        }
    }

    @Async
    public void logSecurityEvent(String securityEvent, String userEmail, String threatLevel,
                                 String description, HttpServletRequest request) {
        try {
            IpAddressService.IpInfo ipInfo = ipAddressService.getDetailedIpInfo(request);

            SecurityLog securityLog = SecurityLog.builder()
                    .timestamp(LocalDateTime.now())
                    .securityEvent(securityEvent)
                    .userEmail(userEmail)
                    .threatLevel(threatLevel)
                    .ipAddress(ipInfo.getIpAddress())
                    .description(description + " | " + ipInfo.toString())
                    .blocked(shouldBlockBasedOnThreat(threatLevel))
                    .build();

            securityLogRepository.save(securityLog);

            log.warn("SECURITY: {} - {} - {} - {} | IP Info: {}",
                    securityEvent, userEmail, threatLevel, description, ipInfo.toString());

            if ("CRITICAL".equals(threatLevel)) {
                notifySecurityTeam(securityLog);
            }

        } catch (Exception e) {
            log.error("Erreur sauvegarde security DB, fallback vers fichier", e);
            log.error("SECURITY_FALLBACK: {} - {} - {} - {}", securityEvent, userEmail, threatLevel, description);
        }
    }

    /**
     * Détermine le niveau de menace basé sur l'événement et l'IP
     */
    private String determineThreatLevel(String eventType, IpAddressService.IpInfo ipInfo) {
        // Événements critiques
        if (eventType.contains("LOGIN_FAILED") && !ipInfo.isLocalhost()) {
            return TypeThreatLevel.MEDIUM.name();
        }

        if (eventType.contains("SECURITY_BREACH") || eventType.contains("UNAUTHORIZED")) {
            return TypeThreatLevel.HIGH.name();
        }

        if (eventType.contains("ADMIN_ACTION") && !ipInfo.isPrivateNetwork()) {
            return TypeThreatLevel.MEDIUM.name();
        }

        return "LOW";
    }

    /**
     * Crée des données additionnelles JSON
     */
    private String createAdditionalData(IpAddressService.IpInfo ipInfo) {
        try {
            Map<String, Object> additionalData = new HashMap<>();
            additionalData.put("isLocalhost", ipInfo.isLocalhost());
            additionalData.put("isPrivateNetwork", ipInfo.isPrivateNetwork());
            additionalData.put("timestamp", LocalDateTime.now().toString());

            return objectMapper.writeValueAsString(additionalData);
        } catch (Exception e) {
            log.warn("Erreur création données additionnelles: {}", e.getMessage());
            return "{}";
        }
    }

    private boolean shouldBlockBasedOnThreat(String threatLevel) {
        return "CRITICAL".equals(threatLevel) || "HIGH".equals(threatLevel);
    }

    private void notifySecurityTeam(SecurityLog securityLog) {
        log.error("🚨 ALERTE CRITIQUE: {} - IP: {}",
                securityLog.getDescription(), securityLog.getIpAddress());
        // TODO: Implémenter notification (email, webhook, etc.)
    }

    /**
     * Méthode pratique pour log audit simple
     */
    public void logUserAction(String action, String userEmail, HttpServletRequest request) {
        logAuditEvent("USER_ACTION", userEmail, action, request, null);
    }

    /**
     * Log spécifique pour les authentifications
     */
    public void logAuthenticationAttempt(String result, String userEmail, HttpServletRequest request) {
        String eventType = "USER_LOGIN_" + result.toUpperCase();
        String details = "Tentative de connexion: " + result;

        logAuditEvent(eventType, userEmail, details, request, null);

        // Si échec, log aussi en sécurité
        if ("FAILED".equals(result.toUpperCase())) {
            logSecurityEvent("LOGIN_FAILURE", userEmail, TypeThreatLevel.MEDIUM.name(),
                    "Échec de connexion", request);
        }
    }

    private String extractSessionId(HttpServletRequest request) {
        try {
            HttpSession session = request.getSession(false);
            if (session != null) {
                return session.getId();
            }
            return "temp-" + UUID.randomUUID().toString().substring(0, 8);
        } catch (Exception e) {
            log.debug("Impossible d'extraire l'ID de session: {}", e.getMessage());
            return "unknown-" + System.currentTimeMillis();
        }
    }

}
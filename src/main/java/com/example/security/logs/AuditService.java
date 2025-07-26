package com.example.security.logs;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@Service
@Slf4j
public class AuditService {

    @Autowired
    private AuditLogRepository auditLogRepository;

    @Autowired
    private SecurityLogRepository securityLogRepository;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Async // Logging asynchrone pour ne pas impacter les performances
    public void logAuditEvent(String eventType, String userEmail, String details,
                              HttpServletRequest request, Long executionTime) {
        try {
            AuditLog auditLog = AuditLog.builder()
                    .timestamp(LocalDateTime.now())
                    .eventType(eventType)
                    .userEmail(userEmail)
                    .details(details)
                    .ipAddress(getClientIpAddress(request))
                    .userAgent(request.getHeader("User-Agent"))
                    .requestUri(request.getRequestURI())
                    .httpMethod(request.getMethod())
                    .sessionId(request.getSession(false) != null ? request.getSession().getId() : null)
                    .executionTime(executionTime)
                    .build();

            auditLogRepository.save(auditLog);

            // Toujours garder un log fichier en backup (sécurité)
            log.info("AUDIT: {} - {} - {}", eventType, userEmail, details);

        } catch (Exception e) {
            // Si la base de données est down, on log quand même dans les fichiers
            log.error("Erreur sauvegarde audit DB, fallback vers fichier", e);
            log.warn("AUDIT_FALLBACK: {} - {} - {}", eventType, userEmail, details);
        }
    }

    @Async
    public void logSecurityEvent(String securityEvent, String userEmail, String threatLevel,
                                 String description, HttpServletRequest request) {
        try {
            SecurityLog securityLog = SecurityLog.builder()
                    .timestamp(LocalDateTime.now())
                    .securityEvent(securityEvent)
                    .userEmail(userEmail)
                    .threatLevel(threatLevel)
                    .ipAddress(getClientIpAddress(request))
                    .description(description)
                    .blocked(shouldBlockBasedOnThreat(threatLevel))
                    .build();

            securityLogRepository.save(securityLog);

            // Log critique toujours en fichier aussi
            log.warn("SECURITY: {} - {} - {} - {}", securityEvent, userEmail, threatLevel, description);

            // Si threat level critique, notification immédiate
            if ("CRITICAL".equals(threatLevel)) {
                notifySecurityTeam(securityLog);
            }

        } catch (Exception e) {
            log.error("Erreur sauvegarde security DB, fallback vers fichier", e);
            log.error("SECURITY_FALLBACK: {} - {} - {} - {}", securityEvent, userEmail, threatLevel, description);
        }
    }

    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    private boolean shouldBlockBasedOnThreat(String threatLevel) {
        return "CRITICAL".equals(threatLevel) || "HIGH".equals(threatLevel);
    }

    private void notifySecurityTeam(SecurityLog securityLog) {
        // Ici vous pourriez envoyer un email, SMS, webhook Slack, etc.
        log.error("🚨 ALERTE CRITIQUE: {}", securityLog.getDescription());
        // TODO: Implémenter notification (email, webhook, etc.)
    }
}
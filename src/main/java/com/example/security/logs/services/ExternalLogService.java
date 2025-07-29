package com.example.security.logs.services;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.scheduling.annotation.Async;
import org.springframework.web.client.RestTemplate;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@Slf4j
public class ExternalLogService {

    private final RestTemplate restTemplate;
    private final boolean elkEnabled;
    private final String logstashUrl;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public ExternalLogService(RestTemplate restTemplate, boolean elkEnabled, String logstashUrl) {
        this.restTemplate = restTemplate;
        this.elkEnabled = elkEnabled;
        this.logstashUrl = logstashUrl;
    }

    @Async
    public void sendToLogstash(String eventType, String userEmail, String details,
                               String ipAddress, String threatLevel) {
        if (!elkEnabled) {
            log.debug("ELK Stack désactivé, skip envoi vers Logstash");
            return;
        }

        try {
            Map<String, Object> logData = new HashMap<>();
            logData.put("@timestamp", LocalDateTime.now().toString());
            logData.put("application", "security-api");
            logData.put("eventType", eventType);
            logData.put("userEmail", userEmail);
            logData.put("details", details);
            logData.put("ipAddress", ipAddress);
            logData.put("threatLevel", threatLevel);
            logData.put("environment", System.getProperty("spring.profiles.active", "unknown"));

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);

            HttpEntity<Map<String, Object>> request = new HttpEntity<>(logData, headers);

            restTemplate.postForEntity(logstashUrl, request, String.class);
            log.debug("Log envoyé vers Logstash: {}", eventType);

        } catch (Exception e) {
            log.error("Erreur envoi vers Logstash: {}", e.getMessage());
            // Fallback vers fichier local
            log.warn("LOGSTASH_FALLBACK: {} - {} - {}", eventType, userEmail, details);
        }
    }

    @Async
    public void sendSecurityAlert(String securityEvent, String userEmail, String threatLevel,
                                  String description, String ipAddress) {
        sendToLogstash(securityEvent, userEmail, description, ipAddress, threatLevel);

        if ("CRITICAL".equals(threatLevel)) {
            sendCriticalAlert(securityEvent, userEmail, description, ipAddress);
        }
    }

    private void sendCriticalAlert(String event, String userEmail, String description, String ipAddress) {
        try {
            Map<String, Object> alert = new HashMap<>();
            alert.put("timestamp", LocalDateTime.now().toString());
            alert.put("severity", "CRITICAL");
            alert.put("event", event);
            alert.put("user", userEmail);
            alert.put("description", description);
            alert.put("source_ip", ipAddress);
            alert.put("application", "security-api");

            log.error("🚨 ALERTE CRITIQUE: {} - {} - IP: {}", event, description, ipAddress);

        } catch (Exception e) {
            log.error("Erreur envoi alerte critique: {}", e.getMessage());
        }
    }
}

package com.example.security.logs;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@Service
public class LogAnalyticsService {

    @Autowired
    private AuditLogRepository auditLogRepository;

    @Autowired
    private SecurityLogRepository securityLogRepository;

    /**
     * Détection automatique d'anomalies
     */
    public Map<String, Object> detectAnomalies() {
        Map<String, Object> anomalies = new HashMap<>();
        LocalDateTime last24h = LocalDateTime.now().minusHours(24);

        // Détection brute force par IP
        auditLogRepository.getTopFailedLoginIPs(last24h).forEach(result -> {
            String ip = (String) result[0];
            Long count = (Long) result[1];

            if (count > 10) { // Plus de 10 tentatives = suspect
                anomalies.put("suspiciousIP_" + ip, Map.of(
                        "ip", ip,
                        "failedAttempts", count,
                        "risk", count > 50 ? "CRITICAL" : count > 20 ? "HIGH" : "MEDIUM"
                ));
            }
        });

        return anomalies;
    }

    /**
     * Génération de rapport de conformité
     */
    public Map<String, Object> generateComplianceReport(LocalDateTime startDate, LocalDateTime endDate) {
        Map<String, Object> report = new HashMap<>();

        // Statistiques période
        Long totalEvents = auditLogRepository.findByTimestampBetween(startDate, endDate, null).getTotalElements();
        Long securityEvents = securityLogRepository.findByTimestampBetween(startDate, endDate, null).getTotalElements();

        report.put("period", Map.of("start", startDate, "end", endDate));
        report.put("totalAuditEvents", totalEvents);
        report.put("totalSecurityEvents", securityEvents);
        report.put("generatedAt", LocalDateTime.now());

        return report;
    }
}

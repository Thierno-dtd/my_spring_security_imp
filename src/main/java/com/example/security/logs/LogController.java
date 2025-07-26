package com.example.security.logs;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/app/v1/admin/logs")
@PreAuthorize("hasRole('ADMIN')") // Seuls les admins peuvent accéder
public class LogController {

    @Autowired
    private AuditLogRepository auditLogRepository;

    @Autowired
    private SecurityLogRepository securityLogRepository;

    /**
     * Dashboard principal - statistiques générales
     */
    @GetMapping("/dashboard")
    public ResponseEntity<Map<String, Object>> getDashboard() {
        Map<String, Object> dashboard = new HashMap<>();

        LocalDateTime last24h = LocalDateTime.now().minusHours(24);
        LocalDateTime last7days = LocalDateTime.now().minusDays(7);

        // Statistiques générales
        dashboard.put("totalAuditLogs", auditLogRepository.count());
        dashboard.put("totalSecurityLogs", securityLogRepository.count());

        // Activité récente
        dashboard.put("logsLast24h", auditLogRepository.findByTimestampBetween(last24h, LocalDateTime.now(), PageRequest.of(0, 1)).getTotalElements());

        // Menaces critiques récentes
        dashboard.put("criticalThreats7days", securityLogRepository.countHighThreatsSince(last7days));

        // Top IPs avec échecs de connexion
        dashboard.put("topFailedLoginIPs", auditLogRepository.getTopFailedLoginIPs(last7days));

        return ResponseEntity.ok(dashboard);
    }

    /**
     * Récupérer les logs d'audit avec pagination et filtres
     */
    @GetMapping("/audit")
    public ResponseEntity<Page<AuditLog>> getAuditLogs(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(required = false) String userEmail,
            @RequestParam(required = false) String eventType,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime startDate,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime endDate) {

        Pageable pageable = PageRequest.of(page, size, Sort.by("timestamp").descending());
        Page<AuditLog> logs;

        if (userEmail != null && !userEmail.isEmpty()) {
            logs = auditLogRepository.findByUserEmailContainingIgnoreCase(userEmail, pageable);
        } else if (eventType != null && !eventType.isEmpty()) {
            logs = auditLogRepository.findByEventType(eventType, pageable);
        } else if (startDate != null && endDate != null) {
            logs = auditLogRepository.findByTimestampBetween(startDate, endDate, pageable);
        } else {
            logs = auditLogRepository.findAll(pageable);
        }

        return ResponseEntity.ok(logs);
    }

    /**
     * Récupérer les logs de sécurité
     */
    @GetMapping("/security")
    public ResponseEntity<Page<SecurityLog>> getSecurityLogs(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(required = false) String threatLevel,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime startDate,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime endDate) {

        Pageable pageable = PageRequest.of(page, size, Sort.by("timestamp").descending());
        Page<SecurityLog> logs;

        if (threatLevel != null && !threatLevel.isEmpty()) {
            logs = securityLogRepository.findByThreatLevel(threatLevel, pageable);
        } else if (startDate != null && endDate != null) {
            logs = securityLogRepository.findByTimestampBetween(startDate, endDate, pageable);
        } else {
            logs = securityLogRepository.findAll(pageable);
        }

        return ResponseEntity.ok(logs);
    }

    /**
     * Analyse des tentatives de connexion échouées par utilisateur
     */
    @GetMapping("/analysis/failed-logins-by-user")
    public ResponseEntity<Map<String, Object>> getFailedLoginsByUser(
            @RequestParam(defaultValue = "24") int hours) {

        LocalDateTime since = LocalDateTime.now().minusHours(hours);
        Map<String, Object> analysis = new HashMap<>();

        // Top utilisateurs avec échecs de connexion
        List<Object[]> failedLogins = auditLogRepository.getTopFailedLoginIPs(since);
        analysis.put("topFailedUsers", failedLogins);
        analysis.put("analysisDate", LocalDateTime.now());
        analysis.put("periodHours", hours);

        return ResponseEntity.ok(analysis);
    }

    /**
     * Recherche textuelle dans les logs
     */
    @GetMapping("/search")
    public ResponseEntity<Page<AuditLog>> searchLogs(
            @RequestParam String query,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {

        Pageable pageable = PageRequest.of(page, size, Sort.by("timestamp").descending());

        // Recherche simple (peut être améliorée avec une recherche full-text)
        Page<AuditLog> logs = auditLogRepository.findByUserEmailContainingIgnoreCase(query, pageable);

        return ResponseEntity.ok(logs);
    }

    /**
     * Export des logs (pour compliance/audit externe)
     */
    @GetMapping("/export")
    @PreAuthorize("hasRole('ADMIN')") // Double vérification pour l'export
    public ResponseEntity<List<AuditLog>> exportLogs(
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime startDate,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime endDate) {

        // Limite à 10000 logs pour éviter la surcharge
        Pageable limit = PageRequest.of(0, 10000, Sort.by("timestamp").ascending());
        Page<AuditLog> logs = auditLogRepository.findByTimestampBetween(startDate, endDate, limit);

        return ResponseEntity.ok(logs.getContent());
    }

    /**
     * Alertes en temps réel
     */
    @GetMapping("/alerts")
    public ResponseEntity<Map<String, Object>> getCurrentAlerts() {
        Map<String, Object> alerts = new HashMap<>();
        LocalDateTime lastHour = LocalDateTime.now().minusHours(1);

        // Vérifier les menaces critiques de la dernière heure
        Long criticalThreats = securityLogRepository.countHighThreatsSince(lastHour);
        alerts.put("criticalThreatsLastHour", criticalThreats);
        alerts.put("alertLevel", criticalThreats > 5 ? "HIGH" : criticalThreats > 0 ? "MEDIUM" : "LOW");

        return ResponseEntity.ok(alerts);
    }
}

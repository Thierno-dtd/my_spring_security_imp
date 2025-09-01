package com.example.security.services;

import com.example.security.configuraton.JwtService;
import com.example.security.dto.SessionInfo;
import com.example.security.dto.SessionStats;
import com.example.security.entites.User;
import com.example.security.entites.UserSession;
import com.example.security.module.auditsLogs.AuditMicroserviceClient;
import com.example.security.repositories.UserSessionRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@Slf4j
@RequiredArgsConstructor
public class SessionService {

    private final UserSessionRepository sessionRepository;
    private final AuditMicroserviceClient auditMicroserviceClient;
    private final JwtService jwtService;

    @Value("${session.timeout.hours:24}")
    private int sessionTimeoutHours;

    @Value("${session.max-concurrent:5}")
    private int maxConcurrentSessions;

    @Value("${session.cleanup.days:30}")
    private int sessionCleanupDays;

    /**
     * Crée une nouvelle session utilisateur
     */
    public String createSession(User user, HttpServletRequest request, String deviceInfo) {
        String sessionId = generateSessionId();

        // Vérifier le nombre de sessions actives
        long activeSessions = sessionRepository.countActiveSessionsByUser(user);

        if (activeSessions >= maxConcurrentSessions) {
            // Fermer les sessions les plus anciennes
            List<UserSession> oldestSessions = sessionRepository.findActiveSessionsByUser(user);
            if (!oldestSessions.isEmpty()) {
                UserSession oldestSession = oldestSessions.get(oldestSessions.size() - 1);
                logoutSession(oldestSession.getSessionId(), "MAX_SESSIONS_EXCEEDED");

                auditMicroserviceClient.logAuditEvent(
                        "SESSION_EVICTED",
                        user.getEmail(),
                        "Session fermée automatiquement (limite atteinte)",
                        request,
                        0L
                );
            }
        }

        UserSession session = UserSession.builder()
                .user(user)
                .sessionId(sessionId)
                .deviceInfo(deviceInfo != null ? deviceInfo : extractDeviceInfo(request))
                .browserInfo(request.getHeader("User-Agent"))
                .ipAddress(extractClientIp(request))
                .location(getLocationFromIp(extractClientIp(request)))
                .expiresAt(LocalDateTime.now().plusHours(sessionTimeoutHours))
                .build();

        sessionRepository.save(session);

        auditMicroserviceClient.logAuditEvent(
                "SESSION_CREATED",
                user.getEmail(),
                "Nouvelle session créée: " + sessionId,
                request,
                0L
        );

        log.debug("🔐 Session créée pour {}: {}", user.getEmail(), sessionId);
        return sessionId;
    }

    /**
     * Récupère les sessions actives d'un utilisateur
     */
    public List<SessionInfo> getActiveSessions(User user, String currentSessionId) {
        List<UserSession> sessions = sessionRepository.findActiveSessionsByUser(user);

        return sessions.stream()
                .map(session -> SessionInfo.builder()
                        .sessionId(session.getSessionId())
                        .deviceInfo(session.getDeviceInfo())
                        .browserInfo(session.getBrowserInfo())
                        .ipAddress(session.getIpAddress())
                        .location(session.getLocation())
                        .lastActivity(session.getLastActivity())
                        .current(session.getSessionId().equals(currentSessionId))
                        .build())
                .collect(Collectors.toList());
    }

    /**
     * Met à jour l'activité d'une session
     */
    public void updateSessionActivity(String sessionId) {
        sessionRepository.findBySessionId(sessionId)
                .ifPresent(session -> {
                    session.setLastActivity(LocalDateTime.now());
                    sessionRepository.save(session);
                });
    }

    /**
     * Ferme une session spécifique
     */
    public boolean logoutSession(String sessionId, String reason) {
        int updated = sessionRepository.logoutSession(sessionId, reason);

        if (updated > 0) {
            sessionRepository.findBySessionId(sessionId).ifPresent(session -> {
                auditMicroserviceClient.logAuditEvent(
                        "SESSION_TERMINATED",
                        session.getUser().getEmail(),
                        "Session fermée: " + reason,
                        null,
                        0L
                );
            });

            log.debug("🚪 Session fermée: {} - Raison: {}", sessionId, reason);
            return true;
        }

        return false;
    }

    /**
     * Ferme toutes les autres sessions d'un utilisateur
     */
    @Transactional
    public int logoutAllOtherSessions(User user, String currentSessionId) {
        int loggedOutSessions = sessionRepository.logoutOtherSessions(
                user,
                currentSessionId,
                "LOGOUT_OTHER_SESSIONS"
        );

        if (loggedOutSessions > 0) {
            auditMicroserviceClient.logAuditEvent(
                    "ALL_OTHER_SESSIONS_TERMINATED",
                    user.getEmail(),
                    loggedOutSessions + " sessions fermées",
                    null,
                    0L
            );

            log.info("🚪 {} autres sessions fermées pour {}", loggedOutSessions, user.getEmail());
        }

        return loggedOutSessions;
    }

    /**
     * Vérifie si une session est valide
     */
    public boolean isSessionValid(String sessionId) {
        return sessionRepository.findBySessionId(sessionId)
                .map(session -> session.getIsActive() && !session.isExpired())
                .orElse(false);
    }

    /**
     * Récupère l'utilisateur d'une session
     */
    public User getUserFromSession(String sessionId) {
        return sessionRepository.findBySessionId(sessionId)
                .filter(session -> session.getIsActive() && !session.isExpired())
                .map(UserSession::getUser)
                .orElse(null);
    }

    /**
     * Nettoyage automatique des sessions expirées
     * Exécuté toutes les heures
     */
    @Scheduled(fixedRate = 3600000) // 1 heure
    @Transactional
    public void cleanupExpiredSessions() {
        try {
            LocalDateTime now = LocalDateTime.now();

            // Désactiver les sessions expirées
            int deactivated = sessionRepository.deactivateExpiredSessions(now);

            if (deactivated > 0) {
                log.info("🧹 {} sessions expirées désactivées", deactivated);
            }

            // Supprimer les anciennes sessions inactives
            LocalDateTime cleanupCutoff = now.minusDays(sessionCleanupDays);
            int deleted = sessionRepository.cleanupOldSessions(cleanupCutoff);

            if (deleted > 0) {
                log.info("🗑️ {} anciennes sessions supprimées", deleted);
            }

        } catch (Exception e) {
            log.error("❌ Erreur lors du nettoyage des sessions", e);
        }
    }

    /**
     * Statistiques des sessions
     */
    public SessionStats getSessionStats() {
        LocalDateTime now = LocalDateTime.now();
        LocalDateTime last24h = now.minusHours(24);
        LocalDateTime last7days = now.minusDays(7);

        // Ces requêtes nécessiteraient des méthodes supplémentaires dans le repository
        return SessionStats.builder()
                .totalActiveSessions(sessionRepository.count())
                .sessionsLast24h(0L) // À implémenter
                .sessionsLast7days(0L) // À implémenter
                .averageSessionDuration(0L) // À implémenter
                .build();
    }

    // Méthodes utilitaires
    private String generateSessionId() {
        return UUID.randomUUID().toString() + "-" + System.currentTimeMillis();
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

    private String extractDeviceInfo(HttpServletRequest request) {
        String userAgent = request.getHeader("User-Agent");
        if (userAgent == null) return "Unknown Device";

        // Détection simple du type d'appareil
        if (userAgent.contains("Mobile")) return "Mobile Device";
        if (userAgent.contains("Tablet")) return "Tablet";
        if (userAgent.contains("Windows")) return "Windows PC";
        if (userAgent.contains("Mac")) return "Mac";
        if (userAgent.contains("Linux")) return "Linux";

        return "Unknown Device";
    }

    private String getLocationFromIp(String ipAddress) {
        // Ici, vous pourriez intégrer un service de géolocalisation IP
        // comme MaxMind GeoIP, ipapi.co, etc.
        // Pour l'instant, retourne une valeur par défaut

        if (ipAddress.equals("127.0.0.1") || ipAddress.equals("::1")) {
            return "Local";
        }

        // Placeholder - à remplacer par vraie géolocalisation
        return "Unknown Location";
    }

    /**
     * Crée une session et retourne le token JWT associé
     */
    public String createSessionWithToken(User user, HttpServletRequest request, String deviceInfo) {
        String sessionId = createSession(user, request, deviceInfo);
        return jwtService.generateTokenWithSession(user, sessionId);
    }

    /**
     * Valide une session via le token JWT
     */
    public boolean validateSessionFromToken(String token) {
        try {
            if (jwtService.isTokenBlacklisted(token)) {
                return false;
            }

            String sessionId = jwtService.extractSessionId(token);
            if (sessionId == null) {
                return false;
            }

            return isSessionValid(sessionId);
        } catch (Exception e) {
            log.error("Erreur validation session depuis token: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Met à jour l'activité de session depuis un token
     */
    public void updateSessionActivityFromToken(String token) {
        try {
            String sessionId = jwtService.extractSessionId(token);
            if (sessionId != null) {
                updateSessionActivity(sessionId);
            }
        } catch (Exception e) {
            log.debug("Impossible de mettre à jour l'activité de session: {}", e.getMessage());
        }
    }

}
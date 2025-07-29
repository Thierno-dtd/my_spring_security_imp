package com.example.security.logs;

import com.example.security.logs.services.AuditService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Component
@Slf4j
public class AuditInterceptor implements HandlerInterceptor {

    @Autowired
    private AuditService auditService;

    private final Set<String> processedRequests = ConcurrentHashMap.newKeySet();

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String requestKey = createRequestKey(request);

        if (processedRequests.contains(requestKey)) {
            log.debug("Requête déjà traitée, éviter doublon: {}", requestKey);
            return true;
        }

        processedRequests.add(requestKey);

        if (processedRequests.size() > 10000) {
            processedRequests.clear();
            log.info("Cache des requêtes audit nettoyé");
        }

        return true;
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) throws Exception {
        if (shouldLogRequest(request) && isUserAuthenticated()) {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            String userEmail = auth.getName();
            String action = determineAction(request, response);

            auditService.logAuditEvent(
                    "API_CALL",
                    userEmail,
                    action + " - Status: " + response.getStatus(),
                    request,
                    null
            );

            log.debug("Audit logged for authenticated user: {} - Action: {}", userEmail, action);
        }
    }

    /**
     * Créer une clé unique pour identifier la requête
     */
    private String createRequestKey(HttpServletRequest request) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String user = (auth != null && auth.isAuthenticated()) ? auth.getName() : "anonymous";

        return String.format("%s:%s:%s:%d",
                request.getMethod(),
                request.getRequestURI(),
                user,
                System.currentTimeMillis() / 1000 // Seconde actuelle
        );
    }

    /**
     * Déterminer si la requête doit être loggée
     */
    private boolean shouldLogRequest(HttpServletRequest request) {
        String uri = request.getRequestURI();
        String method = request.getMethod();

        if (uri.contains("/h2-console") ||
                uri.contains("/swagger") ||
                uri.contains("/v3/api-docs") ||
                uri.contains("/actuator") ||
                uri.contains("/favicon.ico") ||
                uri.contains("/webjars") ||
                uri.contains("/css") ||
                uri.contains("/js")) {
            return false;
        }

        return (uri.contains("/auth/") && !"GET".equals(method)) ||
                (uri.contains("/admin/")) ||
                (uri.contains("/users/") && !"GET".equals(method)) ||
                ("POST".equals(method) || "PUT".equals(method) || "DELETE".equals(method));
    }

    /**
     * Vérifier si l'utilisateur est vraiment authentifié (pas anonymous)
     */
    private boolean isUserAuthenticated() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return auth != null &&
                auth.isAuthenticated() &&
                !"anonymousUser".equals(auth.getName()) &&
                !auth.getAuthorities().stream()
                        .anyMatch(grantedAuthority ->
                                grantedAuthority.getAuthority().equals("ROLE_ANONYMOUS"));
    }

    /**
     * Déterminer l'action basée sur la requête
     */
    private String determineAction(HttpServletRequest request, HttpServletResponse response) {
        String method = request.getMethod();
        String uri = request.getRequestURI();

        if (uri.contains("/authenticate")) return "LOGIN_ATTEMPT";
        if (uri.contains("/registerUser")) return "USER_REGISTRATION";
        if (uri.contains("/registerAdmin")) return "ADMIN_REGISTRATION";
        if (uri.contains("/logout")) return "LOGOUT";
        if (uri.contains("/refresh")) return "TOKEN_REFRESH";

        return String.format("%s %s", method, uri);
    }
}
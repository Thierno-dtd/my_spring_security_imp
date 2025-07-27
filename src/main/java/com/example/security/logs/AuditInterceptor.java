package com.example.security.logs;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

@Component
@RequiredArgsConstructor
@Slf4j
public class AuditInterceptor implements HandlerInterceptor {

    private final AuditService auditService;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        // Stocker le timestamp de début
        request.setAttribute("startTime", System.currentTimeMillis());
        return true;
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response,
                                Object handler, Exception ex) {

        Long startTime = (Long) request.getAttribute("startTime");
        long executionTime = startTime != null ? System.currentTimeMillis() - startTime : 0;

        String uri = request.getRequestURI();

        // Logger les tentatives d'authentification
        if (uri.contains("/auth/")) {
            String eventType = determineEventType(uri, response.getStatus());
            String userEmail = extractUserEmail(request);
            String details = String.format("URI: %s, Status: %d, Method: %s",
                    uri, response.getStatus(), request.getMethod());

            auditService.logAuditEvent(eventType, userEmail, details, request, executionTime);

            // Si échec d'authentification, log sécurité
            if (response.getStatus() == 401 || response.getStatus() == 403) {
                auditService.logSecurityEvent(
                        "AUTHENTICATION_FAILED",
                        userEmail,
                        "MEDIUM",
                        "Échec d'authentification - " + details,
                        request
                );
            }
        }
    }

    private String determineEventType(String uri, int status) {
        if (uri.contains("/authenticate")) {
            return status == 200 ? "USER_LOGIN_SUCCESS" : "USER_LOGIN_FAILED";
        } else if (uri.contains("/register")) {
            return status == 200 ? "USER_REGISTRATION_SUCCESS" : "USER_REGISTRATION_FAILED";
        } else if (uri.contains("/logout")) {
            return "USER_LOGOUT";
        }
        return "AUTHENTICATION_REQUEST";
    }

    private String extractUserEmail(HttpServletRequest request) {
        // Essayer d'extraire depuis le body de la requête (simplifiée)
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null) {
            // Si token présent, extraire l'email (nécessiterait le JwtService)
            return "authenticated_user";
        }
        return "anonymous";
    }
}

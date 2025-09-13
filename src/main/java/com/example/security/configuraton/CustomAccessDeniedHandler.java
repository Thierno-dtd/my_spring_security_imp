package com.example.security.configuraton;

import com.example.security.module.auditsLogs.AuditMicroserviceClient;
import com.example.security.services.AuthenticationService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@Component
@Slf4j
@RequiredArgsConstructor
public class CustomAccessDeniedHandler implements AccessDeniedHandler {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final AuditMicroserviceClient auditClient;
    private final AuthenticationService authenticationService;

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException {

        log.warn("Accès refusé à: {} - {}", request.getRequestURI(), accessDeniedException.getMessage());

        String username = request.getUserPrincipal() != null
                ? request.getUserPrincipal().getName()
                : "anonymous";

        String ip = authenticationService.extractClientIp(request);

        auditClient.logAuditEvent(
                "ACCESS_DENIED_FORBIDDEN",
                username,
                "Tentative d'accès interdit à " + request.getRequestURI() +
                        " depuis IP=" + ip,
                request,
                0L
        );

        response.setContentType("application/json");
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);

        Map<String, Object> errorDetails = new HashMap<>();
        errorDetails.put("timestamp", LocalDateTime.now().toString());
        errorDetails.put("status", 403);
        errorDetails.put("error", "Forbidden");
        errorDetails.put("message", "Accès refusé. Permissions insuffisantes.");
        errorDetails.put("path", request.getRequestURI());

        response.getWriter().write(objectMapper.writeValueAsString(errorDetails));
    }
}

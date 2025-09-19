package com.example.security.services;

import com.example.security.entites.User;
import com.example.security.module.auditsLogs.AuditMicroserviceClient;
import com.example.security.services.AuthenticationService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.Arrays;

/**
 * Aspect pour l'audit automatique des opérations sur les rôles
 */
@Aspect
@Component
@Slf4j
@RequiredArgsConstructor
public class RoleSecurityAspect {

    private final AuditMicroserviceClient auditClient;
    private final AuthenticationService authenticationService;

    /**
     * Audit avant les opérations sensibles de création/modification de rôles
     */
    @Before("execution(* com.example.security.services.RoleService.createRole(..)) || " +
            "execution(* com.example.security.services.RoleService.updateRole(..)) || " +
            "execution(* com.example.security.services.RoleService.deleteRole(..))")
    public void auditRoleOperation(JoinPoint joinPoint) {
        try {
            User currentUser = authenticationService.getCurrentUser();
            HttpServletRequest request = getCurrentHttpRequest();
            String methodName = joinPoint.getSignature().getName();
            String args = Arrays.toString(joinPoint.getArgs());

            auditClient.logSecurityEvent(
                    "ROLE_OPERATION_ATTEMPT",
                    currentUser.getEmail(),
                    "MEDIUM",
                    String.format("Tentative d'opération sur rôle: %s avec arguments: %s", methodName, args),
                    request
            );

        } catch (Exception e) {
            log.warn("Erreur lors de l'audit de l'opération sur rôle", e);
        }
    }

    /**
     * Audit après les assignations/révocations de rôles
     */
    @AfterReturning("execution(* com.example.security.services.UserRoleService.assignRole(..)) || " +
            "execution(* com.example.security.services.UserRoleService.revokeRole(..))")
    public void auditRoleAssignmentOperation(JoinPoint joinPoint) {
        try {
            User currentUser = authenticationService.getCurrentUser();
            HttpServletRequest request = getCurrentHttpRequest();
            String methodName = joinPoint.getSignature().getName();

            auditClient.logSecurityEvent(
                    "ROLE_ASSIGNMENT_COMPLETED",
                    currentUser.getEmail(),
                    "HIGH",
                    String.format("Opération d'assignation de rôle terminée: %s", methodName),
                    request
            );

        } catch (Exception e) {
            log.warn("Erreur lors de l'audit de l'assignation de rôle", e);
        }
    }

    private HttpServletRequest getCurrentHttpRequest() {
        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        return attributes != null ? attributes.getRequest() : null;
    }
}

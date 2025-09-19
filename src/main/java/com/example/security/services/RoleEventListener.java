package com.example.security.services;

import com.example.security.entites.User;
import com.example.security.entites.UserRole;
import com.example.security.module.auditsLogs.AuditMicroserviceClient;
import com.example.security.module.notifications.NotificationClient;
import com.example.security.outils.DataEncryption;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

/**
 * Écouteur d'événements pour les changements de rôles
 */
@Component
@Slf4j
@RequiredArgsConstructor
public class RoleEventListener {

    private final NotificationClient notificationClient;
    private final AuditMicroserviceClient auditClient;
    private final DataEncryption dataEncryption;

    /**
     * Événement déclenché lors de l'assignation d'un rôle
     */
    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void handleRoleAssignment(RoleAssignmentEvent event) {
        try {
            UserRole userRole = event.getUserRole();
            User user = userRole.getUser();
            String decryptedName = dataEncryption.decryptSensitiveData(user.getName());

            // Notification à l'utilisateur
            notificationClient.sendRoleAssignmentNotification(
                    user.getEmail(),
                    decryptedName,
                    userRole.getRole().getName(),
                    userRole.getExpiresAt(),
                    userRole.getAssignedBy()
            );

            // Log détaillé pour monitoring
            log.info("📧 Notification d'assignation de rôle envoyée: {} -> {} ({})",
                    userRole.getRole().getName(), user.getEmail(), userRole.getAssignedBy());

        } catch (Exception e) {
            log.error("Erreur lors de l'envoi de notification d'assignation de rôle", e);
        }
    }

    /**
     * Événement déclenché lors de la révocation d'un rôle
     */
    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void handleRoleRevocation(RoleRevocationEvent event) {
        try {
            UserRole userRole = event.getUserRole();
            User user = userRole.getUser();
            String decryptedName = dataEncryption.decryptSensitiveData(user.getName());

            // Notification à l'utilisateur
            notificationClient.sendRoleRevocationNotification(
                    user.getEmail(),
                    decryptedName,
                    userRole.getRole().getName(),
                    event.getReason(),
                    event.getRevokedBy()
            );

            log.info("📧 Notification de révocation de rôle envoyée: {} <- {} ({})",
                    userRole.getRole().getName(), user.getEmail(), event.getRevokedBy());

        } catch (Exception e) {
            log.error("Erreur lors de l'envoi de notification de révocation de rôle", e);
        }
    }

    /**
     * Événements personnalisés pour les rôles
     */
    public static class RoleAssignmentEvent {
        private final UserRole userRole;

        public RoleAssignmentEvent(UserRole userRole) {
            this.userRole = userRole;
        }

        public UserRole getUserRole() {
            return userRole;
        }
    }

    public static class RoleRevocationEvent {
        private final UserRole userRole;
        private final String reason;
        private final String revokedBy;

        public RoleRevocationEvent(UserRole userRole, String reason, String revokedBy) {
            this.userRole = userRole;
            this.reason = reason;
            this.revokedBy = revokedBy;
        }

        public UserRole getUserRole() {
            return userRole;
        }

        public String getReason() {
            return reason;
        }

        public String getRevokedBy() {
            return revokedBy;
        }
    }
}
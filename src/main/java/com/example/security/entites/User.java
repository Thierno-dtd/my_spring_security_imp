// User.java - MISE À JOUR avec nouveaux champs
package com.example.security.entites;

import com.example.security.constants.AccountStatus;
import com.example.security.constants.TypeRoles;
import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;

@NoArgsConstructor
@AllArgsConstructor
@Data
@Entity
@Table(name = "users")
@Builder
public class User implements UserDetails {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank(message = "Le champs nom ne peut pas être vide.")
    private String name;

    @NotBlank(message = "Le champs prénom ne peut pas être vide.")
    private String pname;

    @Email(message = "L'adresse email n'est pas valide.")
    @Column(unique = true)
    private String email;

    @NotBlank(message = "Le champs password ne peut pas être vide.")
    private String passwd;

    @Column(name = "userRole", nullable = false)
    @Enumerated(EnumType.STRING)
    private TypeRoles roles;

    // Champs de vérification email existants
    @Column(name = "email_verified")
    private Boolean emailVerified = false;

    @Column(name = "email_verification_token")
    private String emailVerificationToken;

    @Column(name = "email_verification_expires_at")
    private LocalDateTime emailVerificationExpiresAt;

    // NOUVEAUX CHAMPS pour récupération de mot de passe
    @Column(name = "password_reset_token")
    private String passwordResetToken;

    @Column(name = "password_reset_expires_at")
    private LocalDateTime passwordResetExpiresAt;

    @Column(name = "password_reset_attempts")
    private Integer passwordResetAttempts = 0;

    @Column(name = "last_password_change")
    private LocalDateTime lastPasswordChange;

    // NOUVEAUX CHAMPS pour changement d'email
    @Column(name = "pending_email")
    private String pendingEmail;

    @Column(name = "email_change_token")
    private String emailChangeToken;

    @Column(name = "email_change_expires_at")
    private LocalDateTime emailChangeExpiresAt;

    // NOUVEAUX CHAMPS pour account lockout
    @Column(name = "failed_login_attempts")
    private Integer failedLoginAttempts = 0;

    @Column(name = "locked_until")
    private LocalDateTime lockedUntil;

    @Column(name = "last_login_attempt")
    private LocalDateTime lastLoginAttempt;

    @Column(name = "last_successful_login")
    private LocalDateTime lastSuccessfulLogin;

    @Column(name = "last_login_ip")
    private String lastLoginIp;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "created_by_admin")
    @JsonIgnore
    private User createdByAdmin;


    // NOUVEAUX CHAMPS pour OAuth2
    @Column(name = "google_id")
    private String googleId;

    @Column(name = "registration_method")
    private String registrationMethod = "EMAIL"; // EMAIL, GOOGLE, etc.

    @Column(name = "profile_picture_url")
    private String profilePictureUrl;

    // Champs existants
    @Column(name = "account_status")
    @Enumerated(EnumType.STRING)
    private AccountStatus accountStatus = AccountStatus.PENDING_VERIFICATION;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        updatedAt = LocalDateTime.now();
        if (emailVerified == null) {
            emailVerified = false;
        }
        if (accountStatus == null) {
            accountStatus = AccountStatus.PENDING_VERIFICATION;
        }
        if (failedLoginAttempts == null) {
            failedLoginAttempts = 0;
        }
        if (passwordResetAttempts == null) {
            passwordResetAttempts = 0;
        }
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(roles.name()));
    }

    @Override
    public String getPassword() {
        return passwd;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return accountStatus != AccountStatus.LOCKED && !isTemporarilyLocked();
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return accountStatus == AccountStatus.ACTIVE && !isTemporarilyLocked();
    }

    // Méthodes utilitaires existantes
    public boolean isEmailVerified() {
        return emailVerified != null && emailVerified;
    }

    public boolean canLogin() {
        return isEmailVerified() && accountStatus == AccountStatus.ACTIVE && !isTemporarilyLocked();
    }

    public boolean hasValidVerificationToken() {
        return emailVerificationToken != null &&
                emailVerificationExpiresAt != null &&
                emailVerificationExpiresAt.isAfter(LocalDateTime.now());
    }

    // NOUVELLES méthodes utilitaires
    public boolean isTemporarilyLocked() {
        return lockedUntil != null && lockedUntil.isAfter(LocalDateTime.now());
    }

    public boolean hasValidPasswordResetToken() {
        return passwordResetToken != null &&
                passwordResetExpiresAt != null &&
                passwordResetExpiresAt.isAfter(LocalDateTime.now());
    }

    public boolean hasValidEmailChangeToken() {
        return emailChangeToken != null &&
                emailChangeExpiresAt != null &&
                emailChangeExpiresAt.isAfter(LocalDateTime.now());
    }

    public void incrementFailedLoginAttempts() {
        this.failedLoginAttempts = (this.failedLoginAttempts == null ? 0 : this.failedLoginAttempts) + 1;
        this.lastLoginAttempt = LocalDateTime.now();
    }

    public void resetFailedLoginAttempts() {
        this.failedLoginAttempts = 0;
        this.lockedUntil = null;
        this.lastSuccessfulLogin = LocalDateTime.now();
    }

    public void lockTemporarily(int lockoutMinutes) {
        this.lockedUntil = LocalDateTime.now().plusMinutes(lockoutMinutes);
    }

    public void incrementPasswordResetAttempts() {
        this.passwordResetAttempts = (this.passwordResetAttempts == null ? 0 : this.passwordResetAttempts) + 1;
    }

    public void resetPasswordResetAttempts() {
        this.passwordResetAttempts = 0;
        this.passwordResetToken = null;
        this.passwordResetExpiresAt = null;
        this.lastPasswordChange = LocalDateTime.now();
    }

    public boolean isGoogleUser() {
        return googleId != null && !googleId.isEmpty();
    }

    public long getMinutesSinceLastLogin() {
        if (lastLoginAttempt == null) return 0;
        return java.time.Duration.between(lastLoginAttempt, LocalDateTime.now()).toMinutes();
    }
}
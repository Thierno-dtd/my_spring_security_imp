package com.example.security.entites;

import com.example.security.constants.AccountStatus;
import com.example.security.constants.TypeRoles;
import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
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
    private int id;
    @NotBlank(message = "Le champs nom ne peut pas être vide.")
    private String name;
    @NotBlank(message = "Le champs prénom ne peut pas être vide.")
    private String pname;
    @Email(message = "L'adresse email n'est pas valide.")
    @Column(unique = true)
    private String email;
    @NotBlank(message = "Le champs password ne peut pas être vide.")
    private String passwd;
    @Column(name = "userRole",nullable = false)
    @Enumerated(EnumType.STRING)
    private TypeRoles roles;
    @Column(name = "email_verified")
    private Boolean emailVerified = false;

    @Column(name = "email_verification_token")
    private String emailVerificationToken;

    @Column(name = "email_verification_expires_at")
    private LocalDateTime emailVerificationExpiresAt;

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
    public boolean isAccountNonLocked() {return accountStatus != AccountStatus.LOCKED;}

    @Override
    public boolean isCredentialsNonExpired() {return true;}

    @Override
    public boolean isEnabled() {return accountStatus == AccountStatus.ACTIVE;}

    // methode utilitaire can login

    public boolean isEmailVerified() {
        return emailVerified != null && emailVerified;
    }

    public boolean canLogin() {
        return isEmailVerified() && accountStatus == AccountStatus.ACTIVE;
    }

    public boolean hasValidVerificationToken() {
        return emailVerificationToken != null &&
                emailVerificationExpiresAt != null &&
                emailVerificationExpiresAt.isAfter(LocalDateTime.now());
    }
}

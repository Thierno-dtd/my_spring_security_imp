package com.example.security.dto;

import com.example.security.constants.AccountStatus;
import com.example.security.constants.TypeRoles;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AccountStatusInfo {
    private boolean exists;
    private boolean emailVerified;
    private AccountStatus accountStatus;
    private boolean canResendVerification;
    private TypeRoles role;
}

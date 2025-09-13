package com.example.security.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class EmailChangeRequest {
    @Email(message = "Format d'email invalide")
    @NotBlank(message = "Le nouvel email est requis")
    private String newEmail;

    @NotBlank(message = "Le mot de passe actuel est requis pour confirmer")
    private String currentPassword;
}
package com.example.security.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class EmailChangeConfirmRequest {
    @NotBlank(message = "Le token de confirmation est requis")
    private String token;
}

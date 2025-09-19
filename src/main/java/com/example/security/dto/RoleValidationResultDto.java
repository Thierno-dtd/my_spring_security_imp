package com.example.security.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RoleValidationResultDto {
    private Boolean isValid;
    private List<String> errors;
    private List<String> warnings;
    private List<RoleConflictDto> conflicts;
    private List<String> missingDependencies;
    private String summary;
}
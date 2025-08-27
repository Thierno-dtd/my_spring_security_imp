package com.example.security.constants;

public enum AccountStatus {
    PENDING_VERIFICATION("En attente de vérification"),
    ACTIVE("Actif"),
    SUSPENDED("Suspendu"),
    LOCKED("Verrouillé");

    private final String displayName;

    AccountStatus(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }
}

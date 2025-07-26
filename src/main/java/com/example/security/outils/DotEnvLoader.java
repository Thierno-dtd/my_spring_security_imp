package com.example.security.outils;

import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Component;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@Component
public class DotEnvLoader {

    @PostConstruct
    public void loadEnv() {
        try {
            Path envFile = Paths.get(".env");
            if (Files.exists(envFile)) {
                Files.lines(envFile)
                        .filter(line -> line.contains("=") && !line.startsWith("#"))
                        .forEach(line -> {
                            String[] parts = line.split("=", 2);
                            System.setProperty(parts[0], parts[1]);
                        });
            }
        } catch (Exception e) {
            System.err.println(e);

        }
    }
}

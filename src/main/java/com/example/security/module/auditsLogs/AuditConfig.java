package com.example.security.module.auditsLogs;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

@Configuration
public class AuditConfig {

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}

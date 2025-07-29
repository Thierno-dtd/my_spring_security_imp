package com.example.security.logs.config;

import com.example.security.logs.services.ExternalLogService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

@Configuration
public class ExternalLoggingConfig {

    @Value("${elk.enabled:false}")
    private boolean elkEnabled;

    @Value("${elk.logstash.url:http://localhost:8080}")
    private String logstashUrl;

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }

    @Bean
    public ExternalLogService externalLogService() {
        return new ExternalLogService(restTemplate(), elkEnabled, logstashUrl);
    }
}
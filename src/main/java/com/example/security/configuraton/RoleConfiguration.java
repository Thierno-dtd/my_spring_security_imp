package com.example.security.configuraton;

import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.context.annotation.EnableAspectJAutoProxy;

/**
 * Configuration pour le module de gestion des rôles
 */
@Configuration
@EnableScheduling
@EnableTransactionManagement
@EnableAspectJAutoProxy
public class RoleConfiguration {

}

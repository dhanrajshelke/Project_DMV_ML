package com.cybersleuth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.client.RestTemplate;

/**
 * CyberSleuth Enterprise Java Backend
 * Orchestrates Security Telemetry, Threat Triage Logging, and Python ML Service Integration.
 */
@SpringBootApplication
public class CyberSecurityApplication {

    public static void main(String[] args) {
        SpringApplication.run(CyberSecurityApplication.class, args);
        System.out.println("==========================================================");
        System.out.println(" ☕ CyberSleuth Java Spring Boot Backend Initialized!");
        System.out.println(" REST API available at: http://localhost:8080/api");
        System.out.println("==========================================================");
    }

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}

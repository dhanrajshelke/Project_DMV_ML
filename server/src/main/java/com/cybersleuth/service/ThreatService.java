package com.cybersleuth.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

@Service
public class ThreatService {

    private final RestTemplate restTemplate;

    @Value("${ml.service.url:http://127.0.0.1:5000}")
    private String mlServiceUrl;

    // In-memory audit log of executed threat scans (demonstrating Java Full Stack state management)
    private final List<Map<String, Object>> scanAuditLog = new ArrayList<>();

    public ThreatService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    /**
     * Checks health status across Java and Python ML tiers.
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> getSystemHealth() {
        Map<String, Object> health = new HashMap<>();
        health.put("javaBackendStatus", "UP");
        health.put("javaVersion", System.getProperty("java.version"));
        health.put("serverTime", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
        health.put("totalAuditsLogged", scanAuditLog.size());

        try {
            Map<String, Object> mlHealth = restTemplate.getForObject(mlServiceUrl + "/api/ml/health", Map.class);
            health.put("pythonMlStatus", "UP");
            health.put("mlDetails", mlHealth);
        } catch (Exception e) {
            health.put("pythonMlStatus", "DOWN");
            health.put("pythonMlError", "ML Service not reachable at " + mlServiceUrl);
        }

        return health;
    }

    /**
     * Proxies and returns sample network flow data for instant testing.
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> getSampleData() {
        try {
            return restTemplate.getForObject(mlServiceUrl + "/api/ml/sample-data", Map.class);
        } catch (Exception e) {
            Map<String, Object> fallback = new HashMap<>();
            fallback.put("error", "Unable to fetch sample data from Python ML service: " + e.getMessage());
            return fallback;
        }
    }

    /**
     * Executes threat triage by calling the Python ML engine,
     * enriches result with Java security metadata, and logs the forensic scan.
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> executeThreatTriage(Map<String, Object> requestPayload) {
        String url = mlServiceUrl + "/api/ml/triage";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<Map<String, Object>> entity = new HttpEntity<>(requestPayload, headers);

        Map<String, Object> mlResult;
        try {
            ResponseEntity<Map> response = restTemplate.postForEntity(url, entity, Map.class);
            mlResult = response.getBody();
        } catch (org.springframework.web.client.HttpStatusCodeException e) {
            Map<String, Object> errorResp = new HashMap<>();
            errorResp.put("status", "VALIDATION_ERROR");
            try {
                com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
                Map body = mapper.readValue(e.getResponseBodyAsString(), Map.class);
                errorResp.put("error", body.get("error"));
                errorResp.put("found_columns", body.get("found_columns"));
                errorResp.put("sample_expected", body.get("sample_expected"));
            } catch (Exception parseEx) {
                errorResp.put("error", e.getResponseBodyAsString());
            }
            return errorResp;
        } catch (Exception e) {
            Map<String, Object> errorResp = new HashMap<>();
            errorResp.put("status", "ERROR");
            errorResp.put("error", "Failed to communicate with Python ML service: " + e.getMessage());
            return errorResp;
        }

        if (mlResult == null) {
            mlResult = new HashMap<>();
        }

        // Add Java Full-Stack orchestration metadata
        String scanId = "SCAN-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase();
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
        
        mlResult.put("scanId", scanId);
        mlResult.put("analyzedAt", timestamp);
        mlResult.put("orchestratedBy", "Java Spring Boot API");

        // Record in Java audit history
        Map<String, Object> auditEntry = new HashMap<>();
        auditEntry.put("scanId", scanId);
        auditEntry.put("timestamp", timestamp);
        
        Map<String, Object> summary = (Map<String, Object>) mlResult.get("summary");
        if (summary != null) {
            auditEntry.put("totalRecords", summary.get("total_records"));
            auditEntry.put("suspiciousCount", summary.get("suspicious_count"));
            auditEntry.put("anomalyCount", summary.get("anomaly_count"));
        }
        
        synchronized (scanAuditLog) {
            scanAuditLog.add(0, auditEntry);
            if (scanAuditLog.size() > 50) {
                scanAuditLog.remove(scanAuditLog.size() - 1);
            }
        }

        return mlResult;
    }

    /**
     * Retrieves recent audit scans logged by the Java service.
     */
    public List<Map<String, Object>> getAuditHistory() {
        synchronized (scanAuditLog) {
            return new ArrayList<>(scanAuditLog);
        }
    }
}

package com.cybersleuth.controller;

import com.cybersleuth.service.ThreatService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = {"http://localhost:5173", "http://localhost:3000", "http://127.0.0.1:5173", "http://127.0.0.1:3000"})
public class ThreatController {

    private final ThreatService threatService;

    public ThreatController(ThreatService threatService) {
        this.threatService = threatService;
    }

    /**
     * System Health Check: returns status of Java Backend and Python ML Microservice.
     */
    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> getHealth() {
        return ResponseEntity.ok(threatService.getSystemHealth());
    }

    /**
     * Execute Threat Detection & Triage.
     * Takes optional network flows, runs ML classification & MITRE ATT&CK mapping.
     */
    @PostMapping("/threats/triage")
    public ResponseEntity<Map<String, Object>> runTriage(@RequestBody(required = false) Map<String, Object> requestPayload) {
        Map<String, Object> result = threatService.executeThreatTriage(requestPayload);
        return ResponseEntity.ok(result);
    }

    /**
     * Get Sample Network Flow Records for zero-config demonstration.
     */
    @GetMapping("/threats/sample-data")
    public ResponseEntity<Map<String, Object>> getSampleData() {
        return ResponseEntity.ok(threatService.getSampleData());
    }

    /**
     * Audit History of Scans executed through the Java Backend.
     */
    @GetMapping("/threats/history")
    public ResponseEntity<List<Map<String, Object>>> getAuditHistory() {
        return ResponseEntity.ok(threatService.getAuditHistory());
    }
}

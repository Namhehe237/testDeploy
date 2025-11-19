package com.example.demo.controller;

import java.util.HashMap;
import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.*;
import org.springframework.security.core.annotation.*;
import org.springframework.web.bind.annotation.*;

import com.example.demo.domain.User;
import com.example.demo.domain.enums.Level;

@RestController
@RequestMapping("/api/test")
public class TestController {

    // ========== PUBLIC ENDPOINTS ==========
    @GetMapping("/public")
    public ResponseEntity<String> publicEndpoint() {
        return ResponseEntity.ok("Endpoint công khai - không cần authenticate");
    }

    // ========== AUTHENTICATED ENDPOINTS ==========
    @GetMapping("/profile")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Map<String, String>> getProfile(@AuthenticationPrincipal User user) {
        return ResponseEntity.ok(Map.of(
                "userId", user.getUserId().toString(),
                "email", user.getEmail(),
                "role", user.getRoleName().toString(),
                "level", user.getLevel().toString()));
    }

    @GetMapping("/authenticated-data")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<String> getAuthenticatedData() {
        return ResponseEntity.ok("Dữ liệu chỉ cho user đã authenticate");
    }

    // ========== LEVEL PERMISSIONS ==========
    @GetMapping("/premium-features")
    @PreAuthorize("hasAuthority('LEVEL_PREMIUM')")
    public ResponseEntity<Map<String, String>> getPremiumFeatures() {
        return ResponseEntity.ok(Map.of(
                "feature1", "Advanced Analytics",
                "feature2", "Priority Support",
                "feature3", "Custom Reports"));
    }

    @PostMapping("/upgrade")
    @PreAuthorize("hasAuthority('LEVEL_FREE')")
    public ResponseEntity<String> upgradeToPremium(@AuthenticationPrincipal User user) {
        return ResponseEntity.ok("User " + user.getEmail() + " đã upgrade lên PREMIUM");
    }

    @GetMapping("/data-with-limit")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Map<String, Object>> getDataWithLimit(@AuthenticationPrincipal User user) {
        Map<String, Object> response = new HashMap<>();
        response.put("data", "Dữ liệu chính");

        if (user.getLevel() == Level.FREE) {
            response.put("limit", "100 requests/day");
        } else {
            response.put("limit", "Unlimited");
        }

        return ResponseEntity.ok(response);
    }

    // ========== ROLE PERMISSIONS ==========
    @GetMapping("/admin/users")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<String> getAllUsers() {
        return ResponseEntity.ok("Danh sách tất cả users (chỉ ADMIN)");
    }

    @DeleteMapping("/admin/users/{userId}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<String> deleteUser(@PathVariable Integer userId) {
        return ResponseEntity.ok("User " + userId + " đã bị xóa (chỉ ADMIN)");
    }

    @GetMapping("/admin/statistics")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<Map<String, Integer>> getStatistics() {
        return ResponseEntity.ok(Map.of(
                "totalUsers", 100,
                "premiumUsers", 25,
                "freeUsers", 75));
    }

    // ========== MIXED PERMISSIONS ==========
    @GetMapping("/advanced-data")
    @PreAuthorize("hasAuthority('ROLE_ADMIN') or hasAuthority('LEVEL_PREMIUM')")
    public ResponseEntity<String> getAdvancedData() {
        return ResponseEntity.ok("Dữ liệu nâng cao (ADMIN hoặc PREMIUM)");
    }

    @PostMapping("/content")
    @PreAuthorize("hasAuthority('ROLE_ADMIN') and hasAuthority('LEVEL_PREMIUM')")
    public ResponseEntity<String> createContent(@RequestBody String content) {
        return ResponseEntity.ok("Content đã tạo (ADMIN hoặc PREMIUM)");
    }

    @GetMapping("/user-only")
    @PreAuthorize("hasAuthority('ROLE_USER')")
    public ResponseEntity<String> getUserData() {
        return ResponseEntity.ok("Dữ liệu chỉ cho USER role (không phải ADMIN)");
    }
}

package com.example.demo.dto;

import com.example.demo.domain.enums.RoleName;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthResponse {
    private Integer userId;
    private String accessToken;
    private RoleName roleName;
}
package com.example.demo.dto;

import com.example.demo.domain.enums.Level;
import com.example.demo.domain.enums.RoleName;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthRequest {
    private String email;
    private String password;
    private RoleName role;
    private Level level;
}
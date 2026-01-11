package com.sneakyzxje.libs.security.service;

import java.util.List;
import java.util.Optional;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import com.sneakyzxje.libs.security.interfaces.TokenStore;
import com.sneakyzxje.libs.security.utils.JwtUtils;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {
    
    private final JwtUtils jwtUtils;
    private final Optional<TokenStore> tokenStore;

    public String processRefresh(String refreshToken) {
        TokenStore store = tokenStore.orElseThrow(() -> new RuntimeException("TokenStore bean not found. Please implement TokenStore interface!"));

        if(!store.isValid(refreshToken)) {
            throw new RuntimeException("Invalid or expired refresh token");
        }
        UserDetails userDetails = store.getUserDetails(refreshToken);
        List<String> roles = userDetails.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .toList();
        return jwtUtils.createAccessToken(userDetails.getUsername(), roles);
    }
}

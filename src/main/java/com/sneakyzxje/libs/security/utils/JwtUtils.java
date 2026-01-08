package com.sneakyzxje.libs.security.utils;

import java.security.Key;
import java.util.Base64;
import java.util.Date;

import org.springframework.stereotype.Component;

import com.sneakyzxje.libs.security.properties.SecurityProperties;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;


@Component
public class JwtUtils {
    private final SecurityProperties securityProperties;
    
    public JwtUtils(SecurityProperties securityProperties) {
        this.securityProperties = securityProperties;
    }
    private Key getSigningKey() {
        byte[] keyBytes = Base64.getDecoder().decode(securityProperties.getAuthentication().getJwtSecret());
        return Keys.hmacShaKeyFor(keyBytes);
    }
    private Claims extractAllClaim(String token) {
        return Jwts.parserBuilder()
        .setSigningKey(getSigningKey())
        .build()
        .parseClaimsJws(token)
        .getBody();
    }

    public String extractUsername(String token) {
        return extractAllClaim(token).getSubject();
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(getSigningKey()).build().parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public String createToken(String subject) {
        long now = System.currentTimeMillis();
        long exp = now + (securityProperties.getAuthentication().getJwtExpiration() * 1000);
        Date issuedAt = new Date(now);
        Date expiredAt = new Date(exp);
        return Jwts.builder()
        .setSubject(subject)
        .signWith(getSigningKey(), io.jsonwebtoken.SignatureAlgorithm.HS256)
        .setIssuedAt(issuedAt)
        .setExpiration(expiredAt)
        .compact();
    }
}

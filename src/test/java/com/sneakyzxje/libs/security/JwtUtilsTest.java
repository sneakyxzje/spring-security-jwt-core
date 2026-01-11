package com.sneakyzxje.libs.security;

import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.sneakyzxje.libs.security.properties.SecurityProperties;
import com.sneakyzxje.libs.security.utils.JwtUtils;

public class JwtUtilsTest {
    
    @Test
    void testCreateTokenSuccess() {
        SecurityProperties securityProperties = new SecurityProperties();

        String secretKey = "enhjY3p4Y3h6Y3p4Y3NkYWRhc2Rhc2Rhc2Rhc2Rhc2Rhc2Rhc2Rhc2Rhc2RzYWRhc2RzYWRhc2R3cTMxMjNhc2Rhc2Rhc2RzYWQ=";

        SecurityProperties.Authentication authentication =  new SecurityProperties.Authentication();
        authentication.setJwtSecret(secretKey);
        authentication.setJwtExpiration(3600);

        securityProperties.setAuthentication(authentication);

        JwtUtils jwtUtils = new JwtUtils(securityProperties);

        List<String> roles = List.of("ADMIN", "USER");
        String token = jwtUtils.createToken("test-user", roles);
        System.out.println("Token generated: " + token);
        
        String username = jwtUtils.extractUsername(token);
        System.out.println("Extract username: " + username);
        Assertions.assertEquals("test-user", username);

        List<String> extRole = jwtUtils.extractRoles(token);
        System.out.println("Extract roles: " + extRole);

        boolean isValid = jwtUtils.validateToken(token);
        Assertions.assertTrue(isValid);
        Assertions.assertNotNull(token); 
        Assertions.assertTrue(token.length() > 20); 
    }
}

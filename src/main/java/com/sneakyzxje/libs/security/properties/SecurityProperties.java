package com.sneakyzxje.libs.security.properties;

import java.util.ArrayList;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "sneaky.jwt")
public class SecurityProperties {

    
    private boolean enabled = false;
    private Authentication authentication = new Authentication();
    private List<String> endpoints = new ArrayList<>();

    public List<String> getEndpoints() {
        return this.endpoints;
    }

    public void setEndpoints(List<String> endpoints) {
        this.endpoints = endpoints;
    }
    
    
    public boolean isEnabled() {
        return this.enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }


    public Authentication getAuthentication() {
        return this.authentication;
    }

    public void setAuthentication(Authentication authentication) {
        this.authentication = authentication;
    }

    public static class Authentication {
        private String jwtSecret = "CHANGE-ME";
        private long jwtExpiration = 86400;

        public String getJwtSecret() {
            return this.jwtSecret;
        }

        public void setJwtSecret(String jwtSecret) {
            this.jwtSecret = jwtSecret;
        }
        
        public long getJwtExpiration() {
            return this.jwtExpiration;
        }

        public void setJwtExpiration(long jwtExpiration) {
            this.jwtExpiration = jwtExpiration;
        }
    }
}

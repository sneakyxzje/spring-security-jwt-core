package com.sneakyzxje.libs.security.interfaces;

import org.springframework.security.core.userdetails.UserDetails;

public interface TokenStore {
    void storeToken(String username, String refreshToken, long expiryTime);

    boolean isValid(String refreshToken);

    void revokeToken(String refreshToken);

    UserDetails getUserDetails(String refreshToken);
}

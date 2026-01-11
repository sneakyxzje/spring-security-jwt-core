[![](https://jitpack.io/v/sneakyxzje/easy-jwt-spring-boot-starter.svg)](https://jitpack.io/#sneakyxzje/easy-jwt-spring-boot-starter)

# Easy JWT Spring Boot Starter

A Spring Boot Starter that helps you integrate **JWT Authentication** quickly and cleanly.  
If you are new to JWT, you can learn more from: [JWT Documentation](https://jwt.io/introduction)

---

## Quick Start

Before getting started, make sure your environment meets the following requirements:

### Requirements

- **Java**: 17+
- **Spring Boot**: 3.x

---

## Installation

This library is hosted on **JitPack**.

### 1. Add the JitPack repository

```xml
<repositories>
    <repository>
        <id>jitpack.io</id>
        <url>https://jitpack.io</url>
    </repository>
</repositories>
```

### 2. Add the dependency

```xml
<dependency>
    <groupId>com.github.sneakyxzje</groupId>
    <artifactId>easy-jwt-spring-boot-starter</artifactId>
    <version>1.0.1</version>
</dependency>
```

## Configuration

Add the following configuration to your `application.properties`

```properties
# JWT secret key (Base64 encoded)
sneaky.jwt.authentication.jwt-secret=YOUR_JWT_SECRET_KEY_HERE

# Access token expiration time (seconds)
sneaky.jwt.authentication.jwt-expiration=60

# Refresh token expiration time (seconds)
sneaky.jwt.authentication.refresh-token-expiration=86400

# Public endpoints (no authentication required)
sneaky.jwt.endpoints=/api/auth/login, /api/auth/register, /public/**

# CORS Configuration:
# Define allowed origins for cross-origin requests
sneaky.jwt.allowed-origins=http://localhost:3000, https://mydomain.com

```

### TokenStore Implementation

The library needs to know where you want to store refresh tokens.
You must create exactly one Spring Bean that implements the TokenStore interface.

```java
@Service
public class MyTokenStore implements TokenStore {

    @Override
    public void storeToken(String username, String refreshToken, long expiryTime) {
        // Save refresh token
    }

    @Override
    public boolean isValid(String refreshToken) {
        // Validate refresh token
    }

    @Override
    public void revokeToken(String refreshToken) {
        // Revoke refresh token
    }

    @Override
    public UserDetails getUserDetails(String refreshToken) {
        // Load UserDetails
    }
}

```

### Usage

Generating Tokens
Inject `JwtUtils` into your authentication service to generate tokens upon login.

```java
@Service
@RequiredArgsConstructor
public class AuthService {

    private final JwtUtils jwtUtils; // Inject from library

    public String login(String username) {
        // 1. Verify credentials...

        // 2. Generate Access Token (with roles)
        List<String> roles = List.of("ROLE_USER", "ROLE_ADMIN");
        String accessToken = jwtUtils.createAccessToken(username, roles);

        // 3. Generate Refresh Token
        RefreshTokenDTO refreshToken = jwtUtils.createRefreshToken();

        // 4. Store logic (using your TokenStore)

        return accessToken;
    }
}
```

Refreshing Token
To refresh an access token, send a POST request to the built-in endpoint:
`POST /easy-auth/refresh`

```json
{
  "refreshToken": "your-refresh-token-uuid"
}
```

### How it works

- Automatically configures the `SecurityFilterChain`.
- Endpoints defined in `sneaky.jwt.endpoints` are permitted without authentication.
- All other requests require authentication.
- The `/easy-auth/refresh` endpoint is always publicly accessible.

> **Note**  
> To keep things simple, the library fully manages Spring Security and JWT filter configuration.  
> No manual `SecurityFilterChain` setup is required.

### Contributing

This library is currently under active development.
If you have ideas for new features, improvements, or bug fixes, feel free to open an issue or submit a pull request.

Happy coding!

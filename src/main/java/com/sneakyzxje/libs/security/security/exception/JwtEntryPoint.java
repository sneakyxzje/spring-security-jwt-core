package com.sneakyzxje.libs.security.security.exception;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import tools.jackson.databind.ObjectMapper;

public class JwtEntryPoint implements AuthenticationEntryPoint {
    
    @Override
    public void commence(HttpServletRequest req, HttpServletResponse res, AuthenticationException exception)
    throws IOException, ServletException {
        System.out.println("Commence running!....");
        res.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        res.setContentType(MediaType.APPLICATION_JSON_VALUE);

        Map<String, Object> body = new HashMap<>();

        body.put("status", 401);
        body.put("error", "Unauthorized");
        body.put("message","Token is invalid or expired");
        body.put("path", req.getServletPath());

        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.writeValue(res.getOutputStream(), body);
    }
}

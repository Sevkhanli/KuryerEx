package org.example.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final CustomUserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");

        // 1. Header Yoxlanışı (Yalnız ACCESS və REFRESH token tələb edən yollar üçün)
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = authHeader.substring(7);
        String email;

        try {
            email = jwtService.findUsername(token);
        } catch (Exception e) {
            // Token vaxtı bitibsə və ya yalnışdırsa, sadəcə set etmədən davam edir.
            filterChain.doFilter(request, response);
            return;
        }

        // 2. Autentifikasiya Yoxlanışı (Yalnız ACCESS Token üçün)
        if (email != null && SecurityContextHolder.getContext().getAuthentication() == null) {

            var userDetails = userDetailsService.loadUserByUsername(email);
            String tokenType = null;

            try {
                tokenType = jwtService.exportToken(token, claims -> (String) claims.get("type"));
            } catch (Exception ignored) {
                // Token tipi çıxarıla bilmirsə, davam edirik (təhlükəsizlik üçün 401 alınacaq)
            }

            // Sadəcə ACCESS tokenlərini qəbul edir.
            if ("ACCESS".equals(tokenType) && jwtService.tokenControl(token, userDetails)) {
                var authToken = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());
                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }

        filterChain.doFilter(request, response);
    }
}
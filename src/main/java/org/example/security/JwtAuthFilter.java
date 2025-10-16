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
        final String requestPath = request.getRequestURI();

        // 1. Token Tələb Olunmayan Yollar üçün Xüsusi Keçid
        // Bu yollarda yoxlama AuthhController-də edilir.
        if (requestPath.equals("/api/auth/verify") || requestPath.equals("/api/auth/resend-otp")) {
            // Header-də token olsa da, olmasa da, birbaşa Controller-ə buraxırıq.
            // Controller özü tokeni yoxlayır və InvalidTokenException (401) atır.
            filterChain.doFilter(request, response);
            return;
        }

        // 2. Header Yoxlanışı (Yalnız ACCESS və REFRESH token tələb edən yollar üçün)
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            // Header yoxdursa, filter zəncirini davam etdir.
            filterChain.doFilter(request, response);
            return;
        }

        String token = authHeader.substring(7);
        String email;

        try {
            email = jwtService.findUsername(token);
        } catch (Exception e) {
            // Token vaxtı bitibsə (qorunan yoldadırsa), sadəcə set etmədən davam edir.
            // Əgər qorunan yoldursa, sonda 401 alınacaq.
            filterChain.doFilter(request, response);
            return;
        }

        // 3. Autentifikasiya Yoxlanışı (Yalnız ACCESS Token üçün)
        if (email != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            // Biz artıq yuxarıda /verify və /resend-otp-ni ayırdıq,
            // ona görə burada sadəcə ACCESS tokenləri yoxlayırıq.

            var userDetails = userDetailsService.loadUserByUsername(email);
            String tokenType = null;

            try {
                tokenType = jwtService.exportToken(token, claims -> (String) claims.get("type"));
            } catch (Exception ignored) {
                // Token tipi çıxarıla bilmirsə, davam edirik (təhlükəsizlik üçün 401 alınacaq)
            }

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

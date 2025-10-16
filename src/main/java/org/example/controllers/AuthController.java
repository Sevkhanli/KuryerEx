package org.example.controllers;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.example.DTOs.request.LoginRequestDTO;
import org.example.DTOs.request.RegisterRequestDTO;
// import org.example.DTOs.request.ResendRequestDTO; // Body DTO-su ləğv edildi
import org.example.DTOs.request.VerifyRequestDTO;
import org.example.DTOs.response.AuthResponseDTO;
import org.example.exceptions.InvalidTokenException;
import org.example.security.JwtService;
import org.example.services.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final UserService userService;
    private final JwtService jwtService;

    @PostMapping("/register")
    public ResponseEntity<AuthResponseDTO> register(@Valid @RequestBody RegisterRequestDTO request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(userService.registerUser(request));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponseDTO> login(@Valid @RequestBody LoginRequestDTO request) {
        return ResponseEntity.ok(userService.loginUser(request));
    }

    // Headers: Authorization: Bearer [VERIFICATION_TOKEN]
    @PostMapping("/verify")
    public ResponseEntity<AuthResponseDTO> verify(
            @RequestHeader("Authorization") String authHeader,
            @Valid @RequestBody VerifyRequestDTO request) {

        String token = authHeader.substring(7); // Tokeni header-dən çıxarırıq
        Long userId = extractUserIdFromVerificationToken(token); // Sadəcə tokeni ötürürük
        return ResponseEntity.ok(userService.verifyUser(userId, request));
    }

    // Headers: Authorization: Bearer [VERIFICATION_TOKEN]
    // *** YENİLƏNMİŞ HİSSƏ: Tokeni yenidən Header-dən qəbul edir ***
    @PostMapping("/resend-otp")
    public ResponseEntity<AuthResponseDTO> resendOtp(
            @RequestHeader("Authorization") String authHeader) {

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new InvalidTokenException("Təsdiqləmə tokeni 'Authorization' header-də tapılmadı və ya düzgün formatda deyil.");
        }

        String token = authHeader.substring(7); // Tokeni 'Bearer ' hissəsindən çıxarırıq

        // Tokenin etibarlılığını yoxlamaq üçün funksiyaya tokeni birbaşa ötürürük.
        Long userId = extractUserIdFromVerificationToken(token);
        userService.resendOtp(userId);

        return ResponseEntity.ok(new AuthResponseDTO(true, "Yeni OTP kodu email ünvanınıza göndərildi."));
    }

    // Headers: Authorization: Bearer [REFRESH_TOKEN]
    @PostMapping("/refresh-token")
    public ResponseEntity<AuthResponseDTO> refreshToken(
            @RequestHeader("Authorization") String authHeader) {

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new InvalidTokenException("Refresh Token 'Authorization' header-də tapılmadı və ya düzgün formatda deyil.");
        }

        String refreshToken = authHeader.substring(7);

        AuthResponseDTO response = userService.refreshToken(refreshToken);

        return ResponseEntity.ok(response);
    }

    /**
     * Tokeni birbaşa qəbul edib User ID-ni tapır və tokenin VERIFICATION növündə olub-olmadığını yoxlayır.
     */
    private Long extractUserIdFromVerificationToken(String token) {
        if (token == null || token.isEmpty()) {
            throw new InvalidTokenException("Təsdiqləmə tokeni boş ola bilməz.");
        }

        // Token növünü yoxlamaq
        Object tokenType = null;
        try {
            tokenType = jwtService.exportToken(token, claims -> claims.get("type"));
        } catch (Exception e) {
            // Token vaxtı bitibsə və ya yalnışdırsa, InvalidTokenException atılır.
            throw new InvalidTokenException("Daxil edilən token etibarlı deyil və ya vaxtı bitib.");
        }

        if (!"VERIFICATION".equals(tokenType)) {
            throw new InvalidTokenException("Daxil edilən token növü təsdiqləmə tokeni deyil.");
        }

        Long userId = jwtService.extractUserId(token);
        if (userId == null) {
            throw new InvalidTokenException("Token etibarlı deyil və ya istifadəçi ID-si yoxdur.");
        }
        return userId;
    }
}

package org.example.controllers;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.example.DTOs.request.LoginRequestDTO;
import org.example.DTOs.request.RegisterRequestDTO;
import org.example.DTOs.request.ResendRequestDTO;
import org.example.DTOs.request.VerifyRequestDTO;
import org.example.DTOs.response.AuthResponseDTO;
import org.example.services.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final UserService userService;

    @PostMapping("/register")
    public ResponseEntity<AuthResponseDTO> register(@Valid @RequestBody RegisterRequestDTO request) {
        AuthResponseDTO response = userService.registerUser(request);
        return new ResponseEntity<>(response, HttpStatus.CREATED); // 201
    }

    @PostMapping("/verify")
    public ResponseEntity<AuthResponseDTO> verify(@Valid @RequestBody VerifyRequestDTO request) {
        userService.verifyUser(request);
        AuthResponseDTO response = new AuthResponseDTO(true, "Email uğurla təsdiqləndi. İndi giriş edə bilərsiniz.");
        return ResponseEntity.ok(response); // 200
    }

    @PostMapping("/resend-otp")
    public ResponseEntity<AuthResponseDTO> resendOtp(@Valid @RequestBody ResendRequestDTO request) {
        userService.resendOtp(request);
        AuthResponseDTO response = new AuthResponseDTO(true, "Yeni OTP kodu email ünvanınıza göndərildi.");
        return ResponseEntity.ok(response); // 200
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponseDTO> login(@Valid @RequestBody LoginRequestDTO request) {
        AuthResponseDTO response = userService.loginUser(request);
        return ResponseEntity.ok(response);
    }
}
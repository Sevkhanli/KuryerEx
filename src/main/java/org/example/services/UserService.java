package org.example.services;

import org.example.DTOs.request.LoginRequestDTO;
import org.example.DTOs.request.RegisterRequestDTO;
import org.example.DTOs.request.VerifyRequestDTO;
import org.example.DTOs.response.AuthResponseDTO;

public interface UserService {
    AuthResponseDTO registerUser(RegisterRequestDTO request);

    // Dəyişiklik: İndi User ID qəbul edir
    AuthResponseDTO verifyUser(Long userId, VerifyRequestDTO request);

    // Dəyişiklik: İndi User ID qəbul edir
    void resendOtp(Long userId);

    AuthResponseDTO loginUser(LoginRequestDTO request);
    // YENİ METOD: Refresh Token-i istifadə edərək yeni tokenlər almaq
    AuthResponseDTO refreshToken(String refreshToken);
}
package org.example.services;

import org.example.DTOs.request.LoginRequestDTO;
import org.example.DTOs.request.RegisterRequestDTO;
import org.example.DTOs.request.ResendRequestDTO;
import org.example.DTOs.request.VerifyRequestDTO;
import org.example.DTOs.response.AuthResponseDTO;

public interface UserService {
    AuthResponseDTO registerUser(RegisterRequestDTO request);

    void verifyUser(VerifyRequestDTO request);

    void resendOtp(ResendRequestDTO request);

    AuthResponseDTO loginUser(LoginRequestDTO request);
}
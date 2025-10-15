package org.example.services.Impl;

import lombok.RequiredArgsConstructor;
import org.example.DTOs.request.LoginRequestDTO;
import org.example.DTOs.request.RegisterRequestDTO;
import org.example.DTOs.request.ResendRequestDTO;
import org.example.DTOs.request.VerifyRequestDTO;
import org.example.DTOs.response.AuthResponseDTO;
import org.example.entities.User;
import org.example.enums.Role;
import org.example.exceptions.*;
import org.example.repositories.UserRepository;
import org.example.security.JwtService;
import org.example.services.MailService;
import org.example.services.UserService;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Random;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final MailService mailService;
    private final AuthenticationManager authenticationManager; // Login üçün
    private final JwtService jwtService; // Login üçün

    // Qeydiyyat (Register)
    @Override
    public AuthResponseDTO registerUser(RegisterRequestDTO request) {
        if (userRepository.existsByPhoneNumber(request.getPhoneNumber())) {
            throw new UserAlreadyExistsException("Bu mobil nömrə artıq qeydiyyatdan keçib.");
        }
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new UserAlreadyExistsException("Bu email artıq qeydiyyatdan keçib.");
        }

        User user = new User();
        user.setFullName(request.getFullName());
        user.setPhoneNumber(request.getPhoneNumber());
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setRole(Role.USER);
        user.setVerified(false); // Başlanğıcda təsdiqlənməyib

        String otpCode = generateOtp();
        user.setOtpCode(otpCode);
        user.setOtpExpirationTime(LocalDateTime.now().plusMinutes(5));

        userRepository.save(user);

        mailService.sendOtpEmail(user.getEmail(), otpCode);

        return new AuthResponseDTO(true, "Qeydiyyat uğurludur. Zəhmət olmasa emailinizi yoxlayıb kodu daxil edin.");
    }

    @Override
    public void verifyUser(VerifyRequestDTO request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new UserNotFoundException("User tapılmadı."));

        if (user.isVerified()) {
            throw new UserAlreadyVerifiedException("Bu istifadəçi artıq təsdiqlənib.");
        }

        if (user.getOtpExpirationTime() == null || user.getOtpExpirationTime().isBefore(LocalDateTime.now())) {
            throw new OtpExpiredException("OTP kodu etibarlı deyil və ya vaxtı bitib.");
        }

        if (!request.getOtpCode().equals(user.getOtpCode())) {
            throw new InvalidOtpException("Daxil etdiyiniz OTP kodu yanlışdır.");
        }

        user.setVerified(true);
        user.setOtpCode(null);
        user.setOtpExpirationTime(null);
        userRepository.save(user);
    }

    @Override
    public void resendOtp(ResendRequestDTO request) {
        User user = userRepository.findByEmailAndIsVerifiedFalse(request.getEmail())
                .orElseThrow(() -> new UserNotFoundException("Təsdiqlənməmiş istifadəçi tapılmadı."));
        String newOtpCode = generateOtp();


        userRepository.save(user);


        mailService.sendOtpEmail(user.getEmail(), newOtpCode);
    }

    @Override
    public AuthResponseDTO loginUser(LoginRequestDTO request) {

        User user = userRepository.findByPhoneNumber(request.getPhoneNumber())
                .orElseThrow(() -> new UserNotFoundException("Mobil nömrə və ya şifrə yanlışdır."));

        if (!user.isVerified()) {
            throw new UserNotVerifiedException("Giriş üçün email təsdiqi tələb olunur.");
        }

        try {

            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            user.getEmail(), // CustomUserDetailsService email ilə işləyir
                            request.getPassword()
                    )
            );

            String token = jwtService.generateToken(user);
            return new AuthResponseDTO(true, "Giriş uğurludur.", token);

        } catch (AuthenticationException e) {
            throw new InvalidCredentialsException("Mobil nömrə və ya şifrə yanlışdır.");
        }
    }



    private String generateOtp() {
        Random random = new Random();
        return String.format("%04d", random.nextInt(10000));
    }
}

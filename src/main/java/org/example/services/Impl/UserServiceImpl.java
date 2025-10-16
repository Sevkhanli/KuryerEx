package org.example.services.Impl;

import lombok.RequiredArgsConstructor;
import org.example.DTOs.request.LoginRequestDTO;
import org.example.DTOs.request.RegisterRequestDTO;
import org.example.DTOs.request.VerifyRequestDTO;
import org.example.DTOs.response.AuthResponseDTO;
import org.example.entities.User;
import org.example.entities.VerificationToken;
import org.example.enums.Role;
import org.example.exceptions.*;
import org.example.repositories.UserRepository;
import org.example.repositories.VerificationTokenRepository;
import org.example.security.JwtService;
import org.example.services.MailService;
import org.example.services.UserService;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Random;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final MailService mailService;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final VerificationTokenRepository tokenRepository;

    // Qeydiyyat (Register)
    @Override
    @Transactional
    public AuthResponseDTO registerUser(RegisterRequestDTO request) {
        if (userRepository.existsByPhoneNumber(request.getPhoneNumber()) || userRepository.existsByEmail(request.getEmail())) {
            throw new UserAlreadyExistsException("Bu nömrə və ya email artıq qeydiyyatdan keçib.");
        }

        User user = new User();
        user.setFullName(request.getFullName());
        user.setPhoneNumber(request.getPhoneNumber());
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setRole(Role.USER);
        user.setVerified(false);

        User savedUser = userRepository.save(user);

        // Yeni istifadəçi olduğu üçün köhnə token yoxdur. Birbaşa yaradılır.
        String otpCode = generateOtp();
        VerificationToken token = new VerificationToken();
        token.setToken(otpCode);
        token.setUser(savedUser);
        token.setExpiryDate(LocalDateTime.now().plusMinutes(5));

        tokenRepository.save(token);

        mailService.sendOtpEmail(user.getEmail(), otpCode);

        String verificationToken = jwtService.generateVerificationToken(user);

        return new AuthResponseDTO(true, "Qeydiyyat uğurludur. Email təsdiqi tələb olunur.", verificationToken);
    }

    // Təsdiqləmə (Verify)
    @Override
    @Transactional
    public AuthResponseDTO verifyUser(Long userId, VerifyRequestDTO request) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException("User tapılmadı."));

        if (user.isVerified()) {
            throw new UserAlreadyVerifiedException("Bu istifadəçi artıq təsdiqlənib.");
        }

        VerificationToken verificationToken = tokenRepository.findByUser(user)
                .orElseThrow(() -> new InvalidOtpException("Təsdiq kodu yoxdur. Zəhmət olmasa təkrar göndərin."));


        if (verificationToken.getExpiryDate().isBefore(LocalDateTime.now())) {
            tokenRepository.delete(verificationToken);
            throw new OtpExpiredException("OTP kodu etibarlı deyil və ya vaxtı bitib. Zəhmət olmasa yenidən göndərin.");
        }

        if (!request.getOtpCode().equals(verificationToken.getToken())) {
            throw new InvalidOtpException("Daxil etdiyiniz OTP kodu yanlışdır.");
        }

        user.setVerified(true);
        userRepository.save(user);

        // Təsdiqləmədən sonra token silinir.
        tokenRepository.delete(verificationToken);

        String accessToken = jwtService.generateToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);

        return new AuthResponseDTO(true, "Email uğurla təsdiqləndi. Giriş tokenləri yaradıldı.", accessToken, refreshToken);
    }

    // OTP-ni Yenidən Göndər (Resend)
    @Override
    @Transactional
    public void resendOtp(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException("User tapılmadı."));

        if (user.isVerified()) {
            throw new UserAlreadyVerifiedException("Bu istifadəçi artıq təsdiqlənib.");
        }

        // *** DÜZƏLİŞ: Duplicate Entry xətasını həll etmək üçün
        // Köhnə tokeni silir və DƏRHALL BAZAYA YAZILMASINI (FLUSH) təmin edirik.
        tokenRepository.findByUser(user).ifPresent(token -> {
            tokenRepository.delete(token);
            tokenRepository.flush(); // Silməni dərhal icra etmək üçün.
        });

        String newOtpCode = generateOtp();
        VerificationToken newToken = new VerificationToken();
        newToken.setToken(newOtpCode);
        newToken.setUser(user);
        newToken.setExpiryDate(LocalDateTime.now().plusMinutes(5));

        // Yeni token yaradılır
        tokenRepository.save(newToken);

        mailService.sendOtpEmail(user.getEmail(), newOtpCode);
    }

    // Giriş (Login)
    @Override
    @Transactional
    public AuthResponseDTO loginUser(LoginRequestDTO request) {

        User user = userRepository.findByPhoneNumber(request.getPhoneNumber())
                .orElseThrow(() -> new UserNotFoundException("Mobil nömrə və ya şifrə yanlışdır."));

        if (!user.isVerified()) {
            // Əgər istifadəçi təsdiqlənməyibsə, ona yeni bir VERIFICATION tokeni veririk.

            // *** DÜZƏLİŞ: Köhnə tokeni silmək və dərhal flush etmək.
            tokenRepository.findByUser(user).ifPresent(token -> {
                tokenRepository.delete(token);
                tokenRepository.flush(); // Silməni dərhal icra etmək üçün.
            });

            String newOtpCode = generateOtp();
            VerificationToken newToken = new VerificationToken();
            newToken.setToken(newOtpCode);
            newToken.setUser(user);
            newToken.setExpiryDate(LocalDateTime.now().plusMinutes(5));
            tokenRepository.save(newToken);

            mailService.sendOtpEmail(user.getEmail(), newOtpCode);

            String verificationToken = jwtService.generateVerificationToken(user);

            throw new UserNotVerifiedException("Giriş üçün email təsdiqi tələb olunur.", verificationToken);
        }

        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            user.getEmail(),
                            request.getPassword()
                    )
            );

            String accessToken = jwtService.generateToken(user);
            String refreshToken = jwtService.generateRefreshToken(user);

            return new AuthResponseDTO(true, "Giriş uğurludur.", accessToken, refreshToken);

        } catch (AuthenticationException e) {
            throw new InvalidCredentialsException("Mobil nömrə və ya şifrə yanlışdır.");
        }
    }

    // REFRESH TOKEN METODU
    @Override
    public AuthResponseDTO refreshToken(String refreshToken) {

        // 1. Tokenin növünü yoxla
        Object tokenType = null;
        try {
            tokenType = jwtService.exportToken(refreshToken, claims -> claims.get("type"));
        } catch (Exception e) {
            throw new InvalidTokenException("Daxil edilən token etibarlı deyil və ya vaxtı bitib.");
        }

        if (!"REFRESH".equals(tokenType)) {
            throw new InvalidTokenException("Daxil edilən token növü Refresh Token deyil.");
        }

        // 2. Refresh Token-dən istifadəçi emailini çıxar
        String userEmail = jwtService.findUsername(refreshToken);

        // 3. İstifadəçini tap
        User user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new UserNotFoundException("Refresh Token-ə uyğun istifadəçi tapılmadı."));

        // 4. Tokenin vaxtının bitib-bitmədiyini yoxla
        if (jwtService.isTokenExpired(refreshToken)) {
            throw new InvalidTokenException("Refresh Token-in vaxtı bitib. Zəhmət olmasa yenidən giriş edin.");
        }

        // 5. Yeni Access Token və Refresh Token yarat
        String newAccessToken = jwtService.generateToken(user);
        String newRefreshToken = jwtService.generateRefreshToken(user);

        return new AuthResponseDTO(true, "Tokenlər uğurla yeniləndi.", newAccessToken, newRefreshToken);
    }


    private String generateOtp() {
        Random random = new Random();
        return String.format("%04d", random.nextInt(10000));
    }
}

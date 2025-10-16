package org.example.DTOs.response;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class AuthResponseDTO {

    private Boolean success;
    private String message;
    private String accessToken;
    private String refreshToken;

    // 1. Uğursuz əməliyyatlar üçün
    public AuthResponseDTO(Boolean success, String message) {
        this.success = success;
        this.message = message;
        this.accessToken = null;
        this.refreshToken = null;
    }

    // 2. Register zamanı qısa müddətli Verification Token üçün
    public AuthResponseDTO(Boolean success, String message, String verificationToken) {
        this.success = success;
        this.message = message;
        this.accessToken = verificationToken; // Verification Token olaraq istifadə olunur
        this.refreshToken = null;
    }

    // 3. Login VƏ Verify zamanı Access + Refresh tokenlər üçün
    public AuthResponseDTO(Boolean success, String message, String accessToken, String refreshToken) {
        this.success = success;
        this.message = message;
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
    }
}
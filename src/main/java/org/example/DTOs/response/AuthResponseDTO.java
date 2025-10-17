package org.example.DTOs.response;

import com.fasterxml.jackson.annotation.JsonInclude; // 1. BU İMPORTU ƏLAVƏ EDİN
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

// 2. BU ANOTASİYANI ƏLAVƏ EDİN
@JsonInclude(JsonInclude.Include.NON_NULL)
@Data
@NoArgsConstructor
public class AuthResponseDTO {

    private Boolean success;
    private String message;
    // Bu sahələr null olduqda JSON-a düşməyəcək
    private String accessToken;
    private String refreshToken;

    // 1. Register, Verify və ya xəta üçün konstruktor (tokenlər null olacaq)
    public AuthResponseDTO(Boolean success, String message) {
        this.success = success;
        this.message = message;
        this.accessToken = null;
        this.refreshToken = null;
    }

    // 2. Login və Refresh üçün konstruktor (tokenlər dolu olacaq)
    public AuthResponseDTO(Boolean success, String message, String accessToken, String refreshToken) {
        this.success = success;
        this.message = message;
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
    }
}
package org.example.DTOs.response;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class AuthResponseDTO {

    private Boolean success;
    private String message;
    private String token;  // JWT token (login zamanı)

    public AuthResponseDTO(Boolean success, String message) {
        this.success = success;
        this.message = message;
        this.token = null;
    }
}
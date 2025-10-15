package org.example.DTOs.request;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class LoginRequestDTO {

    @NotBlank(message = "Mobil nömrə boş ola bilməz")
    private String phoneNumber;

    @NotBlank(message = "Şifrə boş ola bilməz")
    private String password;
}
package org.example.DTOs.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class VerifyRequestDTO {


    @NotBlank(message = "OTP kodu boş ola bilməz")
    @Pattern(regexp = "^[0-9]{4}$", message = "OTP kodu 4 rəqəm olmalıdır")
    private String otpCode;
}
package org.example.handlers;

import org.example.DTOs.response.AuthResponseDTO;
import org.example.exceptions.*;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
public class GlobalExceptionHandler {

    // 404 - Tapılmadı (User, Telefon və ya Email)
    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<AuthResponseDTO> handleUserNotFound(UserNotFoundException ex) {
        return new ResponseEntity<>(
                new AuthResponseDTO(false, ex.getMessage()),
                HttpStatus.NOT_FOUND // 404
        );
    }

    // 409 - Konflikt (Təkrar Məlumat: Register zamanı)
    @ExceptionHandler(UserAlreadyExistsException.class)
    public ResponseEntity<AuthResponseDTO> handleUserAlreadyExists(UserAlreadyExistsException ex) {
        return new ResponseEntity<>(
                new AuthResponseDTO(false, ex.getMessage()),
                HttpStatus.CONFLICT // 409
        );
    }

    // 403 - Girişə İcazə Yoxdur (Təsdiqlənməyib)
    @ExceptionHandler(UserNotVerifiedException.class)
    public ResponseEntity<AuthResponseDTO> handleUserNotVerified(UserNotVerifiedException ex) {
        // Login zamanı təsdiqlənməyibsə, 403 Forbidden və ya 401 Unauthorized qaytara bilərik.
        // 403 daha spesifikdir.
        return new ResponseEntity<>(
                new AuthResponseDTO(false, ex.getMessage()),
                HttpStatus.FORBIDDEN // 403
        );
    }

    // 400 - Səhv Sorğu (OTP və ya etibarsız məlumat)
    @ExceptionHandler({
            InvalidOtpException.class,
            OtpExpiredException.class,
            UserAlreadyVerifiedException.class,
            InvalidCredentialsException.class // Login zamanı şifrə səhvi
    })
    public ResponseEntity<AuthResponseDTO> handleBadRequestExceptions(RuntimeException ex) {
        return new ResponseEntity<>(
                new AuthResponseDTO(false, ex.getMessage()),
                HttpStatus.BAD_REQUEST // 400
        );
    }

}
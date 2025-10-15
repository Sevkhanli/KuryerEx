package org.example.entities;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import lombok.*;
import org.example.enums.Role;

import java.time.LocalDateTime;

@Entity
@Table(name = "users")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String fullName;

    @Column(unique = true)
    private String phoneNumber;

    @Email(message = "email duzgun deyil")
    @Column(name = "email",nullable = false)
    private String email;
    @Column(name = "password",nullable = false)
    private String password;

    private boolean isVerified = false;
    private String otpCode;
    private LocalDateTime otpExpirationTime;


    @Enumerated(EnumType.STRING)
    @Column(name = "role",nullable = false)
    private Role role;
}

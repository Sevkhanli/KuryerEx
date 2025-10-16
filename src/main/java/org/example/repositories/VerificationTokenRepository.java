package org.example.repositories;

import org.example.entities.User;
import org.example.entities.VerificationToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface VerificationTokenRepository extends JpaRepository<VerificationToken, Long> {

    // İstifadəçiyə aid olan aktiv tokeni tapmaq
    Optional<VerificationToken> findByUser(User user);

    // İstifadəçiyə aid olan tokeni silmək (Məsələn: Təkrar göndərəndə)
    void deleteByUser(User user);
}
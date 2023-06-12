package org.example.repository;

import org.example.models.ActivationKey;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface ActivationKeyRepository extends JpaRepository<ActivationKey, Long> {

    Optional<ActivationKey> findByActiveKey(String key);
}

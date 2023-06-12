package org.example.repository;

import org.example.models.ActivationKey;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ActivationKeyRepository extends JpaRepository<ActivationKey, Long> {
    ActivationKey findByActiveKey(String key);
}

package org.example.models;

import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;

@Entity
@Table (name = "activation_key")
@Getter
@Setter
public class ActivationKey {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @OneToOne
    @JoinColumn(nullable = false, name = "user_id")
    private User user;

    @Column(nullable = false)
    private String activeKey;

    @Column(nullable = false)
    private LocalDateTime expirationTime;

    public ActivationKey(User user, String key) {
        this.id = null;
        this.user = user;
        this.activeKey = key;
        this.expirationTime = LocalDateTime.now().plus(10, ChronoUnit.MINUTES);
    }
    public boolean isExpired() {
        return expirationTime.isBefore(LocalDateTime.now());
    }

}

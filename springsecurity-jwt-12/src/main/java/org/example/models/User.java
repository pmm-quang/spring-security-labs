package org.example.models;

import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;

@Entity
@Table(name = "user")
@Getter
@Setter
@NoArgsConstructor
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String username;

    @Column(nullable = false)
    private String password;

    @Column(nullable = false)
    private String email;

    private String name;

    private boolean active;
    private String roles;

    public User(String username, String password, String email, String name) {
        this.id = null;
        this.username = username;
        this.password = password;
        this.email = email;
        this.name = name;
        this.roles = "ROLE_USER";
        this.active = false;
    }
}

package org.example.payload;

import lombok.Data;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;

@Data
public class RegisterRequest {
    @NotBlank(message = "{create.user.invalid.username.null}")
    private String username;

    @NotBlank(message = "{create.user.invalid.password.null}")
    private String password;

    @NotBlank(message = "{create.user.invalid.name.null}")
    private String name;

    @NotBlank(message = "{create.user.invalid.mail.null}")
    @Email(message = "{create.user.invalid.mail.invalid}")
    private String email;
}

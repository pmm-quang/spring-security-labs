package org.example.controller;

import org.example.payload.RegisterRequest;
import org.example.security.jwt.JwtTokenProvider;
import org.example.service.MailService;
import org.example.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.Map;

@RestController
public class RegisterController {
    private final UserService userService;
    private final MailService mailService;

    public RegisterController(UserService userService, MailService mailService) {
        this.userService = userService;
        this.mailService = mailService;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest request) {
        Map<String, String> map = userService.createUser(request);
        String message = mailService.sendMail(map.get("mail"), map.get("key"));
        return ResponseEntity.status(201).body(message);
    }

    @GetMapping(value = "/active", params = "activationKey")
    public ResponseEntity<?> activeUser(@RequestParam String activationKey) {
        String message = userService.activateUser(activationKey);
        return ResponseEntity.ok(message);
    }

}

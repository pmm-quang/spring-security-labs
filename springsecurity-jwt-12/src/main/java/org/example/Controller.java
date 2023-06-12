package org.example;

import org.example.payload.AuthRequest;
import org.example.payload.AuthResponse;
import org.example.models.MyUserDetails;
import org.example.payload.RegisterRequest;
import org.example.security.jwt.JwtTokenProvider;
import org.example.service.MailService;
import org.example.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/")
public class Controller {

    private final UserService userService;
    private final MailService mailService;
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider tokenProvider;

    public Controller(UserService userService, MailService mailService,
                      AuthenticationManager authenticationManager, JwtTokenProvider tokenProvider) {
        this.userService = userService;
        this.mailService = mailService;
        this.authenticationManager = authenticationManager;
        this.tokenProvider = tokenProvider;
    }


    @PostMapping("/auth")
    public ResponseEntity<?> authentication(@RequestBody AuthRequest request) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
        MyUserDetails userDetails = (MyUserDetails) authentication.getPrincipal();
        String jwt = tokenProvider.generateToken(userDetails);
        AuthResponse response = new AuthResponse();
        response.setJwt(jwt);
        return ResponseEntity.ok().body(response);
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest request) {
        Map<String, String> map = userService.createUser(request);
        String message = mailService.sendMail(map.get("mail"), map.get("key"));
        return ResponseEntity.status(201).body(message);
    }

    @GetMapping(value = "/active", params = "activationKey")
    public ResponseEntity<?> activeUser(@RequestParam String activationKey) {
        String message = userService.activateUser(activationKey);
        return ResponseEntity.ok(message);
    }

    @GetMapping("/")
    public String home() {
        return "<h1>Welcome</h1>";
    }

    @GetMapping("/user")
    public String user() {
        return "<h1>Welcome User</h1>";
    }

    @GetMapping("/admin")
    public String admin() {
        return "<h1>Welcome Admin</h1>";
    }
}

package org.example.service;


import org.example.exception.InvalidException;
import org.example.models.ActivationKey;
import org.example.models.User;
import org.example.payload.RegisterRequest;
import org.example.repository.ActivationKeyRepository;
import org.example.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class UserService {
    private static final String CHARACTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    private static final int KEY_LENGTH = 10;
    private final Logger log = LoggerFactory.getLogger(UserService.class);

    private final MessageSource messageSource;
    private final UserRepository userRepo;
    private final ActivationKeyRepository activationKeyRepo;

    public UserService(UserRepository userRepo, ActivationKeyRepository activationKeyRepo, MessageSource messageSource) {
        this.userRepo = userRepo;
        this.activationKeyRepo = activationKeyRepo;
        this.messageSource = messageSource;
    }

    @Transactional
    public Map<String, String> createUser(RegisterRequest request) {
        if (!usernameExists(request.getUsername())
                && !emailExists(request.getEmail())) {
            User user = new User(request.getUsername(), request.getPassword(), request.getEmail(), request.getName());
            User newUser = userRepo.save(user);
            ActivationKey activationKey = new ActivationKey(newUser, generateActivationKey());
            ActivationKey newActivationKey = activationKeyRepo.save(activationKey);
            Map<String, String> map = new HashMap<>();
            map.put("mail", user.getEmail());
            map.put("key", newActivationKey.getActiveKey());
            log.info("created success:" + newUser.getUsername());
            return map;
        }
        log.error("error");
        return null;
    }

    @Transactional
    public String activateUser(String activationKey) {
        ActivationKey key = activationKeyRepo.findByActiveKey(activationKey).orElse(null);
        String messageCode = null;
        if (key != null && !key.isExpired()) {
            User user = key.getUser();
            user.setActive(true);
            userRepo.save(user);
            log.info("Account has been activated: " + user.getUsername());
            messageCode = "account.active.success";
        } else if (key != null && key.isExpired()) {
            activationKeyRepo.delete(key);
            userRepo.delete(key.getUser());
            log.error("The account's activation code has expired: " + key.getUser().getUsername());
            messageCode = "account.active.error";
        } else {
            log.error("Activation code does not exist");
            messageCode = "account.active.error";
        }
        return messageSource.getMessage(messageCode, null, LocaleContextHolder.getLocale());
    }

    // Kiểm tra xem username đã tồn tại hay chưa
    private boolean usernameExists(String username) {
        userRepo.findByUsername(username).ifPresent(
            user -> {
                log.error("Username exists: " + username);
                throw new InvalidException(messageSource.getMessage("create.user.invalid.username.exists", null,
                        LocaleContextHolder.getLocale()));
            }
        );
        return false;
    }

    // Kiểm tra xem email đã tồn tại hay chưa
    private boolean emailExists(String email) {
        userRepo.findByEmail(email).ifPresent(
            user -> {
                log.error("Email exists: " + email);
                throw new InvalidException(messageSource.getMessage("create.user.invalid.mail.exists", null,
                        LocaleContextHolder.getLocale()));
            }
        );
        return false;
    }

    //tạo activation key ngẫu nhiên
    private String generateActivationKey() {
        SecureRandom random = new SecureRandom();
        StringBuilder sb = new StringBuilder(KEY_LENGTH);
        boolean isKeyUnique = false;
        do {
            sb.setLength(0);
            for (int i = 0; i < KEY_LENGTH; i++) {
                int randomIndex = random.nextInt(CHARACTERS.length());
                sb.append(CHARACTERS.charAt(randomIndex));
            }
            isKeyUnique = !activationKeyRepo.findByActiveKey(sb.toString()).isPresent();
        } while (!isKeyUnique);
        return sb.toString();
    }
}

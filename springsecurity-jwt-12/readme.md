# Spring Boot + Spring Security + JWT, register and login
- Trong bài này chúng ta sẽ thực hiện code đăng ký tài khoản và gửi mã xác nhận qua email đăng ký; đăng nhập
***
### Cấu trúc database:

![image](https://github.com/pmm-quang/spring-security-labs/assets/63343138/5b721c57-8236-4b1d-b2c6-e9bf34c7dbfe)

### Biểu đồ tuần tự cho đăng ký tài khoản:

![image](https://github.com/pmm-quang/spring-security-labs/assets/63343138/1457b34f-b005-407a-90de-70d90f7ffb85)

### Cài đặt
- Cài đặt trong file application.yml để kết nối với mySQL database:
```
spring:
  datasource:
    url: jdbc:mysql://localhost:3306/springsecurity
    username: root
    password:
    driver-class-name: com.mysql.cj.jdbc.Driver
```

- Tạo entity **User** tham chiếu với database:
```java
@Entity
@Table(name = "user")
@Getter
@Setter
@NoArgsConstructor
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(nullable = false) private String username;
    @Column(nullable = false) private String password;
    @Column(nullable = false) private String email;
    private String name;
    private boolean active;
    private String roles;
    public User(String username, String password, String email, String name) {
        this.id = null;
        this.username = username;
        this.password = password;
        this.email = email;
        this.name = name;
        this.roles = "ROLE_USER"; // mặc định khi tạo mới user sẽ có role là ROLE_USER
        this.active = false;
    }
    public User() {}
}
```
- Tạo entity **ActivationKey** tham chiếu với database
```java
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
        this.expirationTime = LocalDateTime.now().plus(10, ChronoUnit.MINUTES); //thời gian hết hạn của key là 10 phút sau khi đăng ký
    }
    public ActivationKey() {}
    public boolean isExpired() { // Kiểm tra xem activation key đã hết hạn hay chưa
        return expirationTime.isBefore(LocalDateTime.now());
    }
}
```
- Bảng **user** sẽ lưu thông tin tài khoản, bảng **activation_key** sẽ lưu activation key dùng để kích hoạt tài khoản

- Tạo **UserService** để xử lý login liên quan đến người dùng và kích hoạt tài khoản
```java
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
```
- Sử dụng MessageSource để tải các chuỗi từ các file messages.properties, messages_en.properties, messages_vi.properties.
- Phương thức getMessage() trả về chuỗi văn bản tương ứng với mã đã cho, được tải từ nguồn dữ liệu chuỗi (message bundle) phù hợp với Locale đã chỉ định.


- Tạo **MailService** để xử lý logic liên quan đến gửi mail
- Để làm việc với email, cần thêm vào file pom.xml:
```
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-mail</artifactId>
        </dependency>
```
- Cấu hình trong file application.yml:
```
spring:
  mail:
    host: smtp.gmail.com
    port: 587
    username: 
    password: 
    properties:
      mail:
        smtp:
          auth: true
          starttls.enable: true
```
- username và password là địa chỉ và mật khẩu của email để hệ thống dùng để gửi mail
- ở đây tôi cấu hình mặc định gửi bẳng gmail

**MailService**
```java
@Service
public class MailService {
    private final MessageSource messageSource;
    private final Logger log = LoggerFactory.getLogger(MailService.class);
    private final JavaMailSender mailSender;
    private final HttpServletRequest request;

    public MailService(JavaMailSender mailSender, HttpServletRequest request, MessageSource messageSource) {
        this.mailSender = mailSender;
        this.request = request;
        this.messageSource = messageSource;
    }

    public String sendMail(String mail, String key){
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = null;
        try {
            helper = new MimeMessageHelper(message, true);
            helper.setTo(mail);
            helper.setSubject("Active Account");
            String url = "http://" + request.getServerName() + ":" + request.getServerPort() +
                    "/active?activationKey=" + key;
            String htmlContent =
                    "<html>" +
                            "<body>" +
                            "<p>"+messageSource.getMessage("mailcontent.first", null, LocaleContextHolder.getLocale()) +"</p>" +
                            "<p>"+messageSource.getMessage("mailcontent.second", null, LocaleContextHolder.getLocale())+"</p>" +
                            "<p>" +
                            "<a href=\"" + url + "\">" + messageSource.getMessage("mailcontent.link", null, LocaleContextHolder.getLocale()) + "</a>" +
                            "</p>" +
                            "</body>" +
                            "</html>";
            helper.setText(htmlContent, true);
            mailSender.send(message);
            log.info("Email sending success: " + mail);
            return messageSource.getMessage("checkmail", null, LocaleContextHolder.getLocale());
        } catch (MessagingException e) {
            log.error("Email sending fail!");
            throw new RuntimeException(e);
        }

    }
}
```
###  Triển khai đa ngôn ngữ trong Spring bằng cách sử dụng MessageSource
- Cấu hình MessageSource: Trước tiên, bạn cần cấu hình MessageSource để tải các tài nguyên ngôn ngữ từ các file properties.
```
spring:
  messages:
    basename: i18n/messages
    encoding: UTF-8
```
- Tạo các file properties ngôn ngữ: Trong thư mục resources, tạo thư mục i18n và bên trong tạo các file properties tương ứng cho mỗi ngôn ngữ. Trong project này tôi tạo messages.properties, messages_en.properties, messages_vi.properties

ví dụ trong **messages_en.properties**
```
account.active.success=Your account has been activated.
account.active.error=The activation code has expired!
```
trong **messages_vi.properties**
```
account.active.success=Tài khoản của bạn đã được kích hoạt.
account.active.error=Mã kích hoạt đã hết hạn!
```


### Security
- Ngoài các class đã tạo như bài 8, chúng ta sẽ tạo thêm 2 class nữa để cấu hình jwt là JwtFilter và JwtTokenProvider.

**JwtTokenProvider**:
```java
@Component
public class JwtTokenProvider {
    private final String SECRET_KEY = "secret";
    private final long JWT_EXPIRATION = 604800000L;
```
- SECRET\_KEY đại diện cho khóa bí mật được sử dụng để ký JWT và JWT\_EXPIRATION đại diện cho thời gian hết hạn của JWT tính bằng mili giây.
```java
//Tạo ra jwt từ thông tin user
public String generateToken(MyUserDetails userDetails) {
    Date now  = new Date();
    Date expiryDate = new Date(now.getTime() + JWT_EXPIRATION);
    return Jwts.builder()
            .setSubject(userDetails.getUsername())
            .setIssuedAt(now)
            .setExpiration(expiryDate)
            .signWith(SignatureAlgorithm.HS512, SECRET_KEY)
            .compact();
}
```
- Sử dụng đối tượng Jwts.builder() để bắt đầu xây dựng chuỗi JWT.
- Đặt chủ thể của token bằng cách sử dụng phương thức setSubject() và truyền tên người dùng từ userDetails.getUsername().
- Đặt thời gian bắt đầu (issuedAt) của token bằng cách sử dụng phương thức setIssuedAt() và truyền thời gian hiện tại.
- Đặt thời gian hết hạn của token bằng cách sử dụng phương thức setExpiration() và truyền thời gian hết hạn đã tính toán.
- Ký token bằng thuật toán HS512sử dụng khóa bí mật SECRET\_KEY đã được cấu hình.
- Cuối cùng, sử dụng phương thức compact() để trả về chuỗi JWT đã được tạo.

**JwtFilter**: 
```java
@Component
public class JwtFilter extends OncePerRequestFilter {

    @Autowired
    private MyUserDetailService userDetailService;
    @Autowired
    private JwtTokenProvider tokenProvider;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String jwt = getJwtFromRequest(request); //Lấy chuỗi JWT từ request.
        if (StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt)) { //Kiểm tra xem chuỗi JWT có tồn tại và hợp lệ hay không.
            String username = tokenProvider.getUserFromJWT(jwt); //Nếu chuỗi JWT hợp lệ, trích xuất tên người dùng từ chuỗi JWT
            MyUserDetails userDetails = (MyUserDetails) userDetailService.loadUserByUsername(username); //Sử dụng userDetailService để lấy thông tin chi tiết người dùng dựa trên username.
            if (userDetails != null) {
                //Nếu thông tin chi tiết người dùng tồn tại, tạo một đối tượng UsernamePasswordAuthenticationToken
                //để xác thực người dùng. Đối tượng này được khởi tạo với các tham số là 
                //userDetails, null (mật khẩu không cần thiết trong trường hợp này) và userDetails.getAuthorities() (quyền hạn của người dùng).
                UsernamePasswordAuthenticationToken authentication = new
                        UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

                //Đặt thông tin chi tiết của request vào đối tượng xác thực
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                //Đặt đối tượng xác thực vào SecurityContextHolder để xác thực thành công.
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }
        //Tiếp tục xử lý request bằng cách gọi filterChain.doFilter(request, response)
        //để chuyển tiếp request tới các filter tiếp theo.
        filterChain.doFilter(request, response);
    }

    private String getJwtFromRequest(HttpServletRequest request) {
        String token = request.getHeader("Authorization");
        //Kiểm tra xem header Authorization có chứa thông tin jwt không
        if (StringUtils.hasText(token) && token.startsWith("Bearer ")) {
            return token.substring(7);
        }
        return null;
    }
}
```
- Lớp JwtFilter được sử dụng để xử lý và kiểm tra JWT trong một request HTTP trong ứng dụng.
- Phương thức doFilterInternal(...) được gọi bởi Spring Security để xử lý request và thực hiện xác thực JWT.

**SecurityConfig:**
```java
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private final UserDetailsService userDetailsService;
    private final JwtFilter jwtFilter;
    public SecurityConfig(UserDetailsService userDetailsService, JwtFilter jwtFilter) {
        this.userDetailsService = userDetailsService;
        this.jwtFilter = jwtFilter;
    }
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService);
    }
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .authorizeRequests()
                .antMatchers("/auth", "/", "/register", "/active").permitAll()
                .anyRequest().authenticated()
                .and().sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        http.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
    }
    @Bean
    @Override
    protected AuthenticationManager authenticationManager() throws Exception {
        return super.authenticationManager();
    }
    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }
}
```
- Đặt cấu hình quản lý phiên cho phiên không trạng thái _sessionCreationPolicy(SessionCreationPolicy.STATELESS)_ vì chúng ta sử dụng JWT và không lưu trữ phiên
- Thêm **JwtFilter** trước **UsernamePasswordAuthenticationFilter** để xử lý jwt và xác thực người dùng

**Controller:**

##### - Đăng ký tài khoản:

**RegisterController:**
- API đăng ký:
```java
@PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest request) {
        Map<String, String> map = userService.createUser(request);
        String message = mailService.sendMail(map.get("mail"), map.get("key"));
        return ResponseEntity.status(201).body(message);
    }
```
- userService kiểm tra dữ liệu đầu vào và tạo user nếu hợp lệ
- mailService gửi 1 tin nhắn đến email đăng ký, trong tin nhắn sẽ đính kèm link để xác thực tài khoản, người dùng chỉ cần click vào link trong vòng 10 phút kể từ lúc tạo tài khoản để kích hoạt tài khoản
- API dùng để kích hoạt tài khoản:
```java
@GetMapping(value = "/active", params = "activationKey")
    public ResponseEntity<?> activeUser(@RequestParam String activationKey) {
        String message = userService.activateUser(activationKey);
        return ResponseEntity.ok(message);
    }
```
- Đinh nghĩa cấu trúc dữ liệu đầu vào cho API đăng ký tài khoản:
```java
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
```
- sử dụng các annotation được cung cấp bởi Hibernate Validator, một thư viện sử dụng để xác thực dữ liệu trong ứng dụng Java
- **@NotBlank**: Kiểm tra xem một chuỗi có khác null, không trống và không chỉ chứa các khoảng trắng hay không.
- **@Email**: Kiểm tra xem một chuỗi có đúng định dạng email hay không.
- Nếu các trường đầu vào không đúng quy định sẽ ném ra lỗi mới message được cài đặt trong các file message.properties
- Để sử dụng Hibernate Validator cần thêm vào file pom.xml:
```
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-validation</artifactId>
        </dependency>
```
### Hình minh họa:
- Tạo 1 tài khoản mới:
![image](https://github.com/pmm-quang/spring-security-labs/assets/63343138/c3d5a231-8b2d-4101-91a3-f20c7aa93359)

- Email thông báo yêu cầu kích hoạt:
![image](https://github.com/pmm-quang/spring-security-labs/assets/63343138/ae29bdef-1d2f-4439-b25e-80b9a1ddf64d)

- Kích hoạt thành công:

  ![image](https://github.com/pmm-quang/spring-security-labs/assets/63343138/ebddb70c-3e38-4b0a-9a0e-2a8c8cbaba33)

##### - Đăng nhập:

**AuthController**
- API dùng để đăng nhập:
```java
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
```
- Sử dụng authenticationManager.authenticate() để xác thực người dùng dựa trên tên người dùng và mật khẩu được truyền vào UsernamePasswordAuthenticationToken. Kết quả là một đối tượng Authentication.
- Đặt đối tượng xác thực vào SecurityContextHolder để xác thực thành công bằng cách gọi SecurityContextHolder.getContext().setAuthentication(authentication).
- Lấy thông tin người dùng chi tiết từ đối tượng xác thực bằng cách gọi authentication.getPrincipal().
- Sử dụng tokenProvider.generateToken(userDetails) để tạo chuỗi JWT từ thông tin người dùng.
- Response trả về là 1 chuỗi jwt
- Đinh nghĩa cấu trúc dữ liệu đầu vào cho API đăng nhập:
```java
@Data
public class AuthRequest {
    private String username;
    private String password;
}
```


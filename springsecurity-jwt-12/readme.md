**Spring Boot + Spring Security + JWT, register and login**
- Trong bài này chúng ta sẽ thực hiện code đăng ký tài khoản và gửi mã xác nhận qua email đăng ký; đăng nhập
<h3>Cài đặt</h3>
_pom.xml_
````xml
 <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-data-jpa</artifactId>
        </dependency>
        <dependency>
            <groupId>mysql</groupId>
            <artifactId>mysql-connector-java</artifactId>
            <scope>runtime</scope>
        </dependency>
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt</artifactId>
            <version>0.9.1</version>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-mail</artifactId>
        </dependency>
        <dependency>
            <groupId>org.projectlombok</groupId>
            <artifactId>lombok</artifactId>
        </dependency>
    </dependencies>
````
_application.yml_
````yaml
server:
  port: 8082
spring:
  datasource:
    url: jdbc:mysql://localhost:3306/springsecurity
    username: root
    password:
    driver-class-name: com.mysql.cj.jdbc.Driver
  mail:
    host: smtp.gmail.com
    port: 587
    username: example@gmail.com
    password: 
    properties:
      mail:
        smtp:
          auth: true
          starttls.enable: true
  jpa:
    database-platform: org.hibernate.dialect.MySQL8Dialect
    hibernate:
      ddl-auto: validate
    show-sql: true
````
- Tạo entity **User** tham chiếu với database:
````java
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
````
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
    private final Logger log = LoggerFactory.getLogger(UserService.class);
    private final UserRepository userRepo;
    private final ActivationKeyRepository activationKeyRepo;

    public UserService(UserRepository userRepo, ActivationKeyRepository activationKeyRepo) {
        this.userRepo = userRepo;
        this.activationKeyRepo = activationKeyRepo;
    }
    public Map<String, String> createUser(RegisterRequest request) {
        if (!usernameExists(request.getUsername())
                && !emailExists(request.getEmail())
                && isValidEmail(request.getEmail())) {
            User user = new User(request.getUsername(), request.getPassword(), request.getEmail(), request.getName());
            User newUser = userRepo.save(user);
            ActivationKey activationKey = new ActivationKey(newUser, newUser.getUsername());
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
    public String activateUser(String activationKey) {
        ActivationKey key = activationKeyRepo.findByActiveKey(activationKey);
        if (key != null && !key.isExpired()) {
            User user = key.getUser();
            user.setActive(true);
            userRepo.save(user);
            log.info("Account has been activated: " + user.getUsername());
            return "Your account has been activated.";
        }
        assert key != null;
        log.error("The account's activation code has expired: " + key.getUser().getUsername());
        return "The activation code has expired!";
    }
    // Kiểm tra xem username đã tồn tại hay chưa
    public boolean usernameExists(String username) {
        userRepo.findByUsername(username).ifPresent(
                user -> {
                    log.error("Username exists: " + username);
                    throw new InvalidException("Username exists!");
                }
        );
        return false;
    }
    // Kiểm tra xem email đã tồn tại hay chưa
    public boolean emailExists(String email) {
        userRepo.findByEmail(email).ifPresent(
                user -> {
                    log.error("Email exists: " + email);
                    throw new InvalidException("Email exists!");
                }
        );
        return false;
    }
    //Kiểm tra định dạng email
    public boolean isValidEmail(String email) {
        String regex = "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$";
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(email);
        if (!matcher.matches()) {
            log.error("Email invalidate: " + email);
            throw new InvalidException("Email invalidate!");
        }
        return true;
    }

}
```
- Tạo MailService để xử lý logic liên quan đến gửi mail
```java
@Service
public class MailService {
    private final Logger log = LoggerFactory.getLogger(MailService.class);
    private final JavaMailSender mailSender;
    private final HttpServletRequest request;

    public MailService(JavaMailSender mailSender, HttpServletRequest request) {
        this.mailSender = mailSender;
        this.request = request;
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
                            "<p>Vui lòng click vào đường link bên dưới để kích hoạt tài khoản</p>" +
                            "<br>" +
                            "<p>Lưu ý đường link chỉ có hiệu lực trong vòng 10 phút kể từ lúc đăng ký</p>" +
                            "<p>" +
                                "<a href=\"" + url + "\">" + "Click để active" + "</a>" +
                            "</p>" +
                        "</body>" +
                    "</html>";
            helper.setText(htmlContent, true);
            mailSender.send(message);
            log.info("Email sending success: " + mail);
            return "Please check your mailbox to active your account.";
        } catch (MessagingException e) {
            log.error("Email sending fail!");
            throw new RuntimeException(e);
        }
    }
}
```
### Security
- Ngoài các class đã tạo như bài 8, chúng ta sẽ tạo thêm 2 class nữa để cấu hình jwt là JwtFilter và JwtTokenProvider.

**JwtTokenProvider**:
````java
@Component
public class JwtTokenProvider {
    private final String SECRET_KEY = "secret";
    private final long JWT_EXPIRATION = 604800000L;

````
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
    private String username;
    private String password;
    private String name;
    private String email;
}
```

##### - Đăng nhập:
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


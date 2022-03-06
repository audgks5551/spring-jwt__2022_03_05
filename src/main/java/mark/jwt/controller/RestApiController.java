package mark.jwt.controller;

import lombok.RequiredArgsConstructor;
import mark.jwt.model.User;
import mark.jwt.repository.UserRepository;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
public class RestApiController {

    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final UserRepository userRepository;

    @GetMapping("home")
    public String home() {
        return "<h1>home</h1>";
    }

    @PostMapping("token")
    public String token() {
        return "<h1>token</h1>";
    }

    @PostMapping("login")
    public String login() {
        return "<h1>login</h1>";
    }

    @PostMapping("join")
    public String join(@RequestBody User user) {
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        user.setRoles("ROLE_USER");
        userRepository.save(user);
        return "회원가입완료";
    }

    @GetMapping("/api/v1/user")
    public String user() {
        return "<h1>user</h1>";
    }

    @GetMapping("/api/v1/manager")
    public String manager() {
        return "<h1>manager</h1>";
    }

    @GetMapping("/api/v1/admin")
    public String admin() {
        return "<h1>admin</h1>";
    }
}

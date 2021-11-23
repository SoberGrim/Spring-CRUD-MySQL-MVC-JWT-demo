package com.example.crud.security;

import com.example.crud.repository.UserRepository;
import com.example.crud.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;


import com.example.crud.service.RoleService;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

import static com.example.crud.security.JwtUtils.*;


@RestController
@RequestMapping("/api")
public class JwtController {
    final UserService service;
    final RoleService roleService;
    RefreshTokenRepository refreshTokenRepository;

    @Autowired
    public JwtController(UserService service, RoleService roleService, RefreshTokenRepository refreshTokenRepository) {
        this.service = service;
        this.roleService = roleService;
        this.refreshTokenRepository = refreshTokenRepository;
    }


    static Cookie setCookie(String name, String value, int age) {
        Cookie cookie = new Cookie(name, value);
        cookie.setDomain("localhost");
        cookie.setPath("/");
        cookie.setMaxAge(age);
        cookie.setSecure(true);
        cookie.setHttpOnly(true);
        return cookie;
    }


    @GetMapping("/jwt")
    public String giveJWTToken(HttpServletResponse response)
    {
        String username = "ADMIN";
        String accessToken = generateAccessToken(1L,username);
        RefreshToken refreshToken = generateRefreshToken("1",username,"ADMIN");
        response.addCookie(setCookie("JWT",accessToken,86400));
        response.addCookie(setCookie("JWR", refreshToken.getToken(),86400*10));
        System.out.println("Saving JWT: "+refreshToken);
        refreshTokenRepository.deleteByUserName(username);
        refreshTokenRepository.save(refreshToken);


        return "<a href=\"https://jwt.io/?value="+ accessToken + "\" target=\"_blank\">" + accessToken + "</a><br><br>\n" +
                "<a href=\"https://jwt.io/?value="+ refreshToken + "\" target=\"_blank\">"+ refreshToken +"</a>";
    }

    @GetMapping("/auth")
    public String jwtAuth(HttpServletResponse response, @RequestParam String username, @RequestParam String password)
    {
        String accessToken = generateAccessToken(1L, username);
        RefreshToken refreshToken = generateRefreshToken("1", username, password);
        response.addCookie(setCookie("JWT", accessToken,86400));
        response.addCookie(setCookie("JWR", refreshToken.getToken(),86400*10));
        refreshTokenRepository.save(refreshToken);


        return "<a href=\"https://jwt.io/?value="+ accessToken + "\" target=\"_blank\">" + accessToken + "</a><br><br>\n" +
                "<a href=\"https://jwt.io/?value="+ refreshToken + "\" target=\"_blank\">"+ refreshToken +"</a>";
    }

}
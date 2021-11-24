package com.example.crud.security;

import com.example.crud.model.User;
import com.example.crud.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;


import com.example.crud.service.RoleService;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

import java.security.Principal;

import static com.example.crud.security.JwtUtils.*;
import static com.example.crud.security.ControllerUtils.*;


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


//    @GetMapping("/jwt")
//    public String giveJWTToken(HttpServletResponse response)
//    {
//        String username = "ADMIN";
//        String accessToken = generateAccessToken(1L, username);
//        RefreshToken refreshToken = generateRefreshToken(1L, username);
//        response.addCookie(setCookie("JWT",accessToken,86400));
//        response.addCookie(setCookie("JWR", refreshToken.getToken(),86400*10));
//        System.out.println("Saving JWT: "+refreshToken);
//        refreshTokenRepository.deleteByUserName(username);
//        refreshTokenRepository.save(refreshToken);
//
//
//        return "<a href=\"https://jwt.io/?value="+ accessToken + "\" target=\"_blank\">" + accessToken + "</a><br><br>\n" +
//                "<a href=\"https://jwt.io/?value="+ refreshToken + "\" target=\"_blank\">"+ refreshToken +"</a>";
//    }

    @GetMapping("/jwt")
    public String giveJWTToken(HttpServletResponse response)
    {
        String username = "ADMIN";
        String password = "ADMIN";
        User user = service.getByUsername(username);

        if ( (user!=null) && (user.isPasswordCorrect(password)) )
        {
            if (!user.isEnabled()) {
                return "User disabled";
            }
            if (!user.isAccountNonExpired()) {
                return "Account expired";
            }
            if (!user.isAccountNonLocked()) {
                return "Account locked";
            }
            if (!user.isCredentialsNonExpired()) {
                return "Credentials expired";
            }

            Long id = user.getId();
            String accessToken = generateAccessToken(id, username, 86400);
            RefreshToken refreshToken = generateRefreshToken(id, username, 86400*10);
            response.addCookie(setCookie("JWT", accessToken,86400));
            response.addCookie(setCookie("JWR", refreshToken.getToken(),86400*10));
            refreshTokenRepository.deleteByUserName(username);
            refreshTokenRepository.save(refreshToken);
            return "Successful auth";
        } else {
            return "Wrong credentials";
        }
    }



//http://localhost/api/auth?username=ADMIN&password=ADMIN
    @GetMapping("/auth")
    public String jwtAuth(HttpServletResponse response, @RequestParam("username") String username, @RequestParam("password") String password)
    {
        System.out.println("creditnails"+username+password);
        User user = service.getByUsername(username);

        if ( (user!=null) && (user.isPasswordCorrect(password)) )
        {
            if (!user.isEnabled()) {
                return "User disabled";
            }
            if (!user.isAccountNonExpired()) {
                return "Account expired";
            }
            if (!user.isAccountNonLocked()) {
                return "Account locked";
            }
            if (!user.isCredentialsNonExpired()) {
                return "Credentials expired";
            }

            Long id = user.getId();
            String accessToken = generateAccessToken(id, username, 86400);
            RefreshToken refreshToken = generateRefreshToken(id, username, 86400*10);
            response.addCookie(setCookie("JWT", accessToken,86400));
            response.addCookie(setCookie("JWR", refreshToken.getToken(),86400*10));
            refreshTokenRepository.deleteByUserName(username);
            refreshTokenRepository.save(refreshToken);
            return "Successful auth";
        } else {
            return "Wrong credentials";
        }
    }

    @GetMapping("/logout")
    public ModelAndView jwtLogout(HttpServletResponse response, Principal pr)
    {
        String username = pr.getName();
        if (username!=null) {
            refreshTokenRepository.deleteByUserName(username);
        }
        response.addCookie(setCookie("JWT", "",0));
        response.addCookie(setCookie("JWR", "",0));
        SecurityContextHolder.clearContext();
        return new ModelAndView("index");
    }

}
package com.example.crud.jwt;

import com.example.crud.model.User;
import com.example.crud.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.security.Principal;

import static com.example.crud.jwt.JwtUtils.*;
import static com.example.crud.jwt.CookieUtils.*;


@Controller
@RequestMapping("/api")
public class JwtController {
    final UserService service;
    RefreshTokenRepository refreshTokenRepository;

    @Autowired
    public JwtController(UserService service, RefreshTokenRepository refreshTokenRepository) {
        this.service = service;
        this.refreshTokenRepository = refreshTokenRepository;
    }


    //http://localhost/api/auth?username=ADMIN&password=ADMIN
    @GetMapping("/auth")
    public String jwtAuth(HttpServletResponse response, HttpServletRequest request, @RequestParam("username") String username, @RequestParam("password") String password)
    {
        User user = service.getByUsername(username);

        if ( (user!=null) && (user.isPasswordCorrect(password)) )
        {
            if (!user.isEnabled()) {
                return "redirect:/login?error=AccountDisabled";
            }
            if (!user.isAccountNonExpired()) {
                return "redirect:/login?error=AccountExpired";
            }
            if (!user.isAccountNonLocked()) {
                return "redirect:/login?error=AccountLocked";
            }
            if (!user.isCredentialsNonExpired()) {
                return "redirect:/login?error=CredentialsExpired";
            }

            //set JWT and JWT refresh tokens as cookies
            Long id = user.getId();
            String accessToken = generateAccessToken(id, username, 300);
            RefreshToken refreshToken = generateRefreshToken(id, username, 60*60*24*30);
            response.addCookie(setCookie("JWT", accessToken,300));
            response.addCookie(setCookie("JWR", refreshToken.getToken(),60*60*24*30));

            //save JWT refresh token in DB (delete previous one if needed)
            refreshTokenRepository.deleteByUserName(username);
            refreshTokenRepository.save(refreshToken);

            //authorize User
            UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
            auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(auth);

            return "redirect:/index";
        } else {
            return "redirect:/login?error=WrongCredentials";
        }
    }

    //http://localhost/api/logout
    @GetMapping("/logout")
    public String jwtLogout(HttpServletResponse response, Principal pr)
    {
        String username = pr.getName();
        if (username!=null) {
            refreshTokenRepository.deleteByUserName(username);
            response.addCookie(setCookie("JWT", "",0));
            response.addCookie(setCookie("JWR", "",0));
            SecurityContextHolder.clearContext();
        }
        return "redirect:/login";
    }

}
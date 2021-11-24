package com.example.crud.security;

import com.example.crud.model.User;
import com.example.crud.model.UserRole;
import com.example.crud.service.UserService;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.security.Principal;
import java.util.ArrayList;

public class ControllerUtils {
    public static String getCookieFromRequest(HttpServletRequest request, String name) {
        Cookie[] cookies = request.getCookies();
        if (cookies!=null)
            for (Cookie cookie: cookies) {
                if (cookie.getName().equals(name)){
                    return cookie.getValue();
                }
            }
        return null;
    }


}

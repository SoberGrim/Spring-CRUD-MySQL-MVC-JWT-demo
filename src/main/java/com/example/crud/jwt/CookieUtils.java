package com.example.crud.jwt;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;


public class CookieUtils {

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

    static Cookie setCookie(String name, String value, int age) {
        Cookie cookie = new Cookie(name, value);
        cookie.setDomain("localhost");
        cookie.setPath("/");
        cookie.setMaxAge(age);
        cookie.setSecure(true);
        cookie.setHttpOnly(true);
        return cookie;
    }

}

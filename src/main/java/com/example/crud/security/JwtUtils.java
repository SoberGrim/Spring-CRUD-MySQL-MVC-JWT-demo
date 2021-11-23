package com.example.crud.security;

import io.jsonwebtoken.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JwtUtils {
    enum JwtTokenStatus {
        TOKEN_VALID,
        TOKEN_EXPIRED,
        TOKEN_MALFORMED,
        TOKEN_BAD_SIGNATURE,
        TOKEN_ILLEGAL
    }


    public static String generateAccessToken(Long id, String username) {
        Date now = new Date(System.currentTimeMillis());
        Date expiry = new Date(now.getTime() + 1000 * 60 * 2);
        return Jwts.builder()
                .setSubject(id.toString())
                .claim("username", username)
                .claim("roles", "ADMIN USER")
                .setIssuedAt(now)
                .setExpiration(expiry)
                .setIssuer("token-issuer")
                .setAudience("partner_id")
                .signWith(SignatureAlgorithm.HS256, "your-256-bit-secret".getBytes(StandardCharsets.UTF_8)) // new byte[]{'a','s'}
                .compact();
    }

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

    public static RefreshToken generateRefreshToken(String id, String username, String password) {
        Date now = new Date(System.currentTimeMillis());
        Date expiry = new Date(now.getTime() + 1000 * 60 * 60 * 24 * 24);

        String token = Jwts.builder()
                .setSubject(id)
                .claim("username", username)
                .setExpiration(expiry)
                .signWith(SignatureAlgorithm.HS256, "your-256-bit-secret".getBytes(StandardCharsets.UTF_8))
                .compact();
        return new RefreshToken(token, id, username, expiry);
    }

    public static Long getUserIdFromJwt(String token) {
        Claims claim = Jwts.parser().setSigningKey("your-256-bit-secret".getBytes(StandardCharsets.UTF_8)).parseClaimsJws(token).getBody();
        String id;
        try {
            id = claim.getSubject();
        } catch (Exception e) {
            System.out.println("[Filter] JWT token has no subject");
            return 0L;
        }
        return Long.parseLong(id);
    }


    public static String getFieldFromJwt(String token, String field) {
        Claims claim = Jwts.parser().setSigningKey("your-256-bit-secret".getBytes(StandardCharsets.UTF_8)).parseClaimsJws(token).getBody();
        String username;
        try {
            username = claim.get(field).toString();
        } catch (Exception e) {
            System.out.println("[Filter] JWT token has no " + field);
            return "";
        }
        return username;
    }

    public static JwtTokenStatus checkToken(String token) {
        System.out.println("Checking token: " + token);

        try {
            Claims claims = Jwts.parser().setSigningKey("your-256-bit-secret".getBytes(StandardCharsets.UTF_8)).parseClaimsJws(token).getBody();
            System.out.println(claims.toString());
            return JwtTokenStatus.TOKEN_VALID;
        } catch (ExpiredJwtException e) {
            System.out.println("[Filter] JWT token expired");
            return JwtTokenStatus.TOKEN_EXPIRED;
        } catch (MalformedJwtException e) {
            System.out.println("[Filter] JWT token malformed");
            return JwtTokenStatus.TOKEN_MALFORMED;
        } catch (SignatureException e) {
            System.out.println("[Filter] JWT token - bad signature");
            return JwtTokenStatus.TOKEN_BAD_SIGNATURE;
        } catch (IllegalArgumentException e) {
            System.out.println("[Filter] JWT token - illegal argument");
            return JwtTokenStatus.TOKEN_ILLEGAL;
        }
    }


}

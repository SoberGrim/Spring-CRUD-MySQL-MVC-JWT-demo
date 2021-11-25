package com.example.crud.jwt;

import io.jsonwebtoken.*;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JwtUtils {
    public static final String jwtSecret = "your-256-bit-secret";

    enum JwtTokenStatus {
        TOKEN_VALID,
        TOKEN_EXPIRED,
        TOKEN_MALFORMED,
        TOKEN_BAD_SIGNATURE,
        TOKEN_ILLEGAL,
        TOKEN_UNSUPPORTED
    }

    public static String generateAccessToken(Long id, String username, int maxAgeInSec) {
        Date now = new Date(System.currentTimeMillis());
        Date expiry = new Date(now.getTime() + maxAgeInSec * 1000L);
        return Jwts.builder()
                .setSubject(id.toString())
                .claim("username", username)
                .claim("roles", "ADMIN USER")
                .setIssuedAt(now)
                .setExpiration(expiry)
                .setIssuer("token-issuer")
                .setAudience("partner_id")
                .signWith(SignatureAlgorithm.HS256, jwtSecret.getBytes(StandardCharsets.UTF_8)) // new byte[]{'a','s'}
                .compact();
    }

    public static RefreshToken generateRefreshToken(Long id, String username, int maxAgeInSec) {
        Date now = new Date(System.currentTimeMillis());
        Date expiry = new Date(now.getTime() + maxAgeInSec * 1000L);

        String token = Jwts.builder()
                .setSubject(id.toString())
                .claim("username", username)
                .setExpiration(expiry)
                .signWith(SignatureAlgorithm.HS256, jwtSecret.getBytes(StandardCharsets.UTF_8))
                .compact();
        return new RefreshToken(token, id.toString(), username, expiry);
    }

    public static Long getUserIdFromJwt(String token) {
        Claims claim = Jwts.parser().setSigningKey(jwtSecret.getBytes(StandardCharsets.UTF_8)).parseClaimsJws(token).getBody();
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
        Claims claim = Jwts.parser().setSigningKey(jwtSecret.getBytes(StandardCharsets.UTF_8)).parseClaimsJws(token).getBody();
        String username;
        try {
            username = claim.get(field).toString();
        } catch (Exception e) {
            System.out.printf("[Filter] JWT token has no %s\n", field);
            return "";
        }
        return username;
    }

    public static JwtTokenStatus checkToken(String token) {
        System.out.println("Checking token: " + token);
        try {
            Claims claims = Jwts.parser().setSigningKey(jwtSecret.getBytes(StandardCharsets.UTF_8)).parseClaimsJws(token).getBody();
            System.out.println(claims.toString());
            long expiresIn = (claims.getExpiration().getTime() - System.currentTimeMillis()) / 1000;
            System.out.printf("[checkToken] Token expires in %ss\n", expiresIn);
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
        } catch (UnsupportedJwtException e) {
            System.out.println("[Filter] JWT token unsupported");
            return JwtTokenStatus.TOKEN_UNSUPPORTED;
        }
    }


}

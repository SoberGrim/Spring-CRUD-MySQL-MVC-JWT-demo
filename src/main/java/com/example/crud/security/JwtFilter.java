package com.example.crud.security;


import com.example.crud.model.User;
import com.example.crud.repository.UserRepository;
import com.example.crud.service.RoleService;
import com.example.crud.service.UserService;
import io.jsonwebtoken.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Date;

@Configuration
public class JwtFilter extends OncePerRequestFilter {
    final UserService service;
   // final String jwtSecret;

    @Autowired
    public JwtFilter(UserService service) {
        this.service = service;
 //       this.jwtSecret = env.getProperty("jwt.secret");
    }


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        System.out.println("[Filter] " + request.getMethod() + ' ' + request.getRequestURL()
                + " ["+request.getLocalPort() + "<-" + request.getRemoteHost()+':' + request.getRemotePort()+"] "
                + "User: "+request.getRemoteUser() + ", session: "+request.getRequestedSessionId());

        String jwt = getCookieFromRequest(request,"JWT");
       // System.out.println("JWT: " + jwt);
        Boolean tokenIsValid = validateToken(jwt);
        System.out.println("Toked is valid? : " +  tokenIsValid);

        if (tokenIsValid) {
            Long uid = getUserIdFromJwt(jwt);
         //   System.out.println("user id: " + uid);
            User user = service.getById(uid);
          //  System.out.println("user: "+ user);
            UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
          //  System.out.println(auth);
            auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
           // System.out.println(auth);
            //If everything goes fine, set authentication to Security context holder
            SecurityContextHolder.getContext().setAuthentication(auth);

        }


        filterChain.doFilter(request, response);
       // if (StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt)) {
//        if (StringUtils.hasText(jwt)) {
//            //Extract user id from jwt token
//            Long userId = 1L;//tokenProvider.getUserIdFromJwt(jwt);
//
//           // SecurityUser user = (SecurityUser) userDetailsService.loadUserById(userId);
//            User user = service.getById(userId);
//            //System.out.println("jwt filter user:"+user);
//
//
//            UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
//            auth.setDetails(new WebAuthenticationDetailsSource()
//                    .buildDetails(request));
//            //If everything goes fine, set authentication to Security context holder
//            SecurityContextHolder.getContext().setAuthentication(auth);
//
//        } else {
//
//
//            filterChain.doFilter(request, response);
//        }
    }

    private String getCookieFromRequest(HttpServletRequest request, String name) {
        Cookie[] cookies = request.getCookies();
        if (cookies!=null)
        for (Cookie cookie: cookies) {
            if (cookie.getName().equals(name)){
                return cookie.getValue();
            }
        }
        return null;
    }

    public boolean validateToken(String token) {
        System.out.println("Token: "+token);
      //  System.out.println(jwtSecret);
      //  Jws<Claims> claimsJws = Jwts.parser().setSigningKey("your-256-bit-secret".getBytes(StandardCharsets.UTF_8)).parseClaimsJws(token);

       try {
           Claims claims = Jwts.parser().setSigningKey("your-256-bit-secret".getBytes(StandardCharsets.UTF_8)).parseClaimsJws(token).getBody();
           System.out.println(claims.toString());
           return true;
       } catch (ExpiredJwtException e) {
           System.out.println("[Filter] JWT token expired");
       } catch (MalformedJwtException e) {
           System.out.println("[Filter] JWT token malformed");
       } catch (SignatureException e) {
           System.out.println("[Filter] JWT token - bad signature");
       } catch (IllegalArgumentException e) {
           System.out.println("[Filter] JWT token - illegal argument");
       }
                //.parseClaimsJws(token).getBody().getExpiration().before(new Date());
     //   System.out.println(nonExpired);
      //  System.out.println(claimsJws);
     //   System.out.println(claimsJws.getBody().getExpiration()+" nonexpired?"+claimsJws.getBody().getExpiration().before(new Date()));
//        try {
//            Jws<Claims> claimsJws = Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token);
//            return !claimsJws.getBody().getExpiration().before(new Date());
//        } catch (ExpiredJwtException | MalformedJwtException | SignatureException |
//                IllegalArgumentException e) {
//            throw new RuntimeException("Invalid token");
//        }
        return false;
    }

    public Long getUserIdFromJwt(String token) {
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

}

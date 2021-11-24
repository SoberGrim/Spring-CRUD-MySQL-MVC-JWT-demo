package com.example.crud.security;


import com.example.crud.model.User;
import com.example.crud.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static com.example.crud.security.JwtController.setCookie;
import static com.example.crud.security.JwtUtils.*;
import static com.example.crud.security.ControllerUtils.*;
import static com.example.crud.security.JwtUtils.JwtTokenStatus.*;

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

        //todo jwt logout?

        String jwt = getCookieFromRequest(request,"JWT");
        if (jwt == null) {
            System.out.println("[" + request.getRemotePort()+"] Token status: none");
            filterChain.doFilter(request, response);
            return;
        }

        JwtTokenStatus tokenStatus = checkToken(jwt);
        System.out.println("[" + request.getRemotePort()+"] Token status: " +  tokenStatus);

        if (tokenStatus==TOKEN_EXPIRED) {
            String jwr = getCookieFromRequest(request,"JWR");
            JwtTokenStatus tokenRefreshStatus = checkToken(jwr);
            if (tokenRefreshStatus==TOKEN_VALID) {
                System.out.println("[" + request.getRemotePort()+"] JWT refresh token is valid");
                Long uid = getUserIdFromJwt(jwr);
                String username = getFieldFromJwt(jwr,"username");
                User user = service.getById(uid);
                if (user.getUsername().equals(username)) {
                    //todo refresh jwt token
                    String newJwt = generateAccessToken(uid, username, 86400);
                    JwtTokenStatus newTokenStatus = checkToken(newJwt);
                    jwt = newJwt;
                    tokenStatus = newTokenStatus;

                    response.addCookie(setCookie("JWT", newJwt,86400));
                    System.out.println("[" + request.getRemotePort()+"] JWT token refreshed via JWT Refresh token");
                }
            } else {
                System.out.println("[" + request.getRemotePort()+"] JWT expired, JWR is invalid");
            }
            //todo refresh token needs refresh?
        }


        if (tokenStatus== TOKEN_VALID) {
            Long uid = getUserIdFromJwt(jwt);
            //String username = getUsernameFromJwt(jwt);
            String username = getFieldFromJwt(jwt,"username");
            //jwt -> id -> find user in DB. users username from DB == "username" from jwt token?
            User user = service.getById(uid);
            if (user.getUsername().equals(username)) {
                UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
                auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                //If everything goes fine, set authentication to Security context holder
                SecurityContextHolder.getContext().setAuthentication(auth);
            }
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




}

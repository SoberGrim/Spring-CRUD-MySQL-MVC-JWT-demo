package com.example.crud.jwt;


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

import static com.example.crud.jwt.JwtUtils.*;
import static com.example.crud.jwt.CookieUtils.*;
import static com.example.crud.jwt.JwtUtils.JwtTokenStatus.*;

@Configuration
public class JwtFilter extends OncePerRequestFilter {
    final UserService service;
    RefreshTokenRepository refreshTokenRepository;

    @Autowired
    public JwtFilter(UserService service, RefreshTokenRepository refreshTokenRepository) {
        this.service = service;
        this.refreshTokenRepository = refreshTokenRepository;
    }


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        //skip auth filter if user is authorized
        if ((SecurityContextHolder.getContext().getAuthentication() != null) && (SecurityContextHolder.getContext().getAuthentication().isAuthenticated())) {
            filterChain.doFilter(request, response);
            return;
        }

        int remotePort = request.getRemotePort();
        //skip auth if user has no JWT token
        String jwt = getCookieFromRequest(request, "JWT");
        if (jwt == null) {
            System.out.printf("[%s] Token status: none\n", remotePort);
            filterChain.doFilter(request, response);
            return;
        }

        System.out.printf("[Filter] %s %s [%s<-%s:%s] User %s, session: %s\n",
                request.getMethod(), request.getRequestURL(), request.getLocalPort(), request.getRemoteHost(), request.getRemotePort(), request.getRemoteUser(), request.getRequestedSessionId());


        JwtTokenStatus tokenStatus = checkToken(jwt);
        System.out.printf("[%s] Token status: %s\n", remotePort, tokenStatus);

        if (tokenStatus == TOKEN_EXPIRED) {
            String jwr = getCookieFromRequest(request, "JWR");
            JwtTokenStatus tokenRefreshStatus = checkToken(jwr);
            if (tokenRefreshStatus == TOKEN_VALID) {
                System.out.printf("[%s] JWT refresh token is valid\n", remotePort);
                Long uid = getUserIdFromJwt(jwr);

                if (refreshTokenRepository.findByToken(jwr).isPresent()) {
                    String username = getFieldFromJwt(jwr, "username");
                    User user = service.getById(uid);
                    if (user.getUsername().equals(username)) {
                        String newJwt = generateAccessToken(uid, username, 86400);
                        JwtTokenStatus newTokenStatus = checkToken(newJwt);
                        jwt = newJwt;
                        tokenStatus = newTokenStatus;

                        response.addCookie(setCookie("JWT", newJwt, 86400));
                        System.out.printf("[%s] JWT token refreshed via JWT Refresh token\n", remotePort);
                    }

                }
            } else {
                System.out.printf("[%s] JWT expired, JWR is invalid\n", remotePort);
            }
            //todo refresh token needs refresh?
        }


        if (tokenStatus == TOKEN_VALID) {
            Long uid = getUserIdFromJwt(jwt);
            String username = getFieldFromJwt(jwt, "username");

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
    }

}

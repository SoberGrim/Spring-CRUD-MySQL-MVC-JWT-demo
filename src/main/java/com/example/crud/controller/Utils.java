package com.example.crud.controller;

import com.example.crud.model.User;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;

import com.example.crud.model.UserDTO;
import com.example.crud.model.UserRole;
import com.example.crud.service.UserService;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.util.*;

@Component
public class Utils {
//    final String jwtSecret;
//    @Autowired
//    public Utils(Environment env) {
//        this.jwtSecret = env.getProperty("jwt.secret");
//    }

    static void checkLoginEmailBusy(UserDTO userdto, BindingResult bindingResult, UserService service) {
        User editedUser = service.getByUsername(userdto.getUsername());
        if ((editedUser != null) && (!editedUser.getId().toString().equals(userdto.getId()))) {
            bindingResult.addError(new FieldError("username", "username", "Username already taken"));
        }
        editedUser = service.getByEmail(userdto.getEmail());
        if ((editedUser != null) && (!editedUser.getId().toString().equals(userdto.getId()))) {
            bindingResult.addError(new FieldError("email", "email", "User with this email already exists"));
        }
    }

    static UserDTO parseBindingErrors(BindingResult bindingResult) {
        UserDTO userError = new UserDTO();
        userError.setId(
                (bindingResult.getFieldErrorCount("id")>0)?
                        Objects.requireNonNull(bindingResult.getFieldError("id")).getDefaultMessage():"");
        userError.setUsername(
                (bindingResult.getFieldErrorCount("username")>0)?
                        Objects.requireNonNull(bindingResult.getFieldError("username")).getDefaultMessage():"");
        userError.setPassword(
                (bindingResult.getFieldErrorCount("password")>0)?
                        Objects.requireNonNull(bindingResult.getFieldError("password")).getDefaultMessage():"");
        userError.setEmail(
                (bindingResult.getFieldErrorCount("email")>0)?
                        Objects.requireNonNull(bindingResult.getFieldError("email")).getDefaultMessage():"");
        userError.setAge(
                (bindingResult.getFieldErrorCount("age")>0)?
                        Objects.requireNonNull(bindingResult.getFieldError("age")).getDefaultMessage():"");
        userError.setFirstname(
                (bindingResult.getFieldErrorCount("firstname")>0)?
                        Objects.requireNonNull(bindingResult.getFieldError("firstname")).getDefaultMessage():"");
        userError.setLastname(
                (bindingResult.getFieldErrorCount("lastname")>0)?
                        Objects.requireNonNull(bindingResult.getFieldError("lastname")).getDefaultMessage():"");

        return userError;
    }

    static User getPrincipal(Principal pr, Authentication authentication, UserService service) {
        User principal = service.getByUsername(pr.getName());
        if (principal == null) {
            principal = new User();
            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            String prUsername = userDetails.getUsername();
            principal.setEmail("deleted");
            principal.setUsername(prUsername);
            ArrayList<GrantedAuthority> authArr = new ArrayList<>(userDetails.getAuthorities());
            for (GrantedAuthority auth : authArr) {
                principal.addRole(new UserRole(auth.getAuthority()));
            }
        }
        return principal;
    }



}

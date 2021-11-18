package com.example.crud.controller;

import com.example.crud.model.User;
import com.example.crud.repository.UserRepository;
import com.example.crud.service.UserService;
import org.springframework.http.*;
import org.springframework.security.access.annotation.Secured;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import org.springframework.web.client.RestTemplate;
import com.example.crud.model.HTTPRequest;
import com.example.crud.model.UserDTO;
import com.example.crud.service.RoleService;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import java.net.http.HttpResponse;
import java.util.*;

import static com.example.crud.controller.Utils.*;


@RestController
@RequestMapping("/api")
public class APIRestController {
    final UserService service;
    final RoleService roleService;

    @Autowired
    public APIRestController(UserService service, UserRepository repository , RoleService roleService) {
        this.service = service;
        this.roleService = roleService;
    }


    @Secured("ROLE_ADMIN")
    @GetMapping("/users")
    List<User> userList() {
        return service.getFilterUsers(false);
    }

    @PostMapping("/register")
    UserDTO register(@RequestBody @Valid UserDTO tempUser, BindingResult bindingResult) {
        tempUser.setRoleStr("GUEST");
        return createNewUser(tempUser, bindingResult);
    }

    @Secured("ROLE_ADMIN")
    @PostMapping("/new")
    UserDTO createNewUser(@RequestBody @Valid UserDTO tempUser, BindingResult bindingResult) {
        System.out.println(bindingResult);
        Utils.checkLoginEmailBusy(tempUser, bindingResult, service);
        UserDTO userErrorDTO = Utils.parseBindingErrors(bindingResult);
        if (bindingResult.hasErrors()) {
            userErrorDTO.setErrorsPresent(true);
        } else {
            User user = new User();
            user.merge(tempUser, roleService.getRoles(tempUser.getRoleStr()));
            service.update(user);
        }

        return userErrorDTO;
    }


    @Secured("ROLE_ADMIN")
    @PatchMapping("/edit")
    UserDTO editUser(@RequestBody @Valid UserDTO tmpUser, BindingResult bindingResult) {

        String idStr = tmpUser.getId();
        Long id = idStr.matches("\\d+")?Long.parseLong(idStr):0;
        User user = service.getById(id);

        Utils.checkLoginEmailBusy(tmpUser, bindingResult, service);
        UserDTO userErrorDTO = Utils.parseBindingErrors(bindingResult);

        if (bindingResult.hasErrors()) {
            userErrorDTO.setErrorsPresent(true);
            System.out.println("UserFields have errors: "+userErrorDTO);
        } else {
            user.merge(tmpUser, roleService.getRoles(tmpUser.getRoleStr()));
            service.update(user);
        }

        return userErrorDTO;
    }

    @Secured("ROLE_ADMIN")
    @PostMapping("/search")
    void searchUser(@RequestBody UserDTO tmpUser) {
        User user = new User();
        user.merge(tmpUser, roleService.getRoles(tmpUser.getRoleStr()));
        service.setFilter(user, false);
    }

    @Secured("ROLE_ADMIN")
    @PostMapping("/filter")
    void filterUser(@RequestBody UserDTO tmpUser) {
        User user = new User();
        user.merge(tmpUser, roleService.getRoles(tmpUser.getRoleStr()));
        service.setFilter(user, true);
    }

    @Secured("ROLE_ADMIN")
    @GetMapping("/removefilter")
    void removeFilter() {
        service.removeFilter();
    }

    @Secured("ROLE_ADMIN")
    @DeleteMapping("/delete")
    void deleteUserById(@RequestBody String idStr) {
        Long id = idStr.matches("\\d+")?Long.parseLong(idStr):0;
        service.delete(id);
    }


    @GetMapping("/jwt")
    public String giveJWTToken(HttpServletResponse response)
    {
        String accessToken = generateAccessToken("1","ADMIN","ADMIN");
        String refreshToken = generateRefreshToken("1","ADMIN","ADMIN");

        Cookie cookie = new Cookie("Token", accessToken);
        cookie.setDomain("localhost");
        cookie.setPath("/");
        cookie.setMaxAge(86400);
        cookie.setSecure(true);
        cookie.setHttpOnly(true);
        response.addCookie(cookie);
      //  response.setHeader("Set-Cookie", cookie+ "; SameSite=strict");
//        response.setHeader("Authorization", accessToken);
//        response.setHeader("Access-Control-Expose-Headers", "authorization");

        return "<a href=\"https://jwt.io/?value="+ accessToken + "\" target=\"_blank\">" + accessToken + "</a><br><br>\n" +
                "<a href=\"https://jwt.io/?value="+ refreshToken + "\" target=\"_blank\">"+ refreshToken +"</a>";
    }



    String cookies="";
    @PostMapping("/proxy")
    String proxy(@RequestBody HTTPRequest request) {
        HttpMethod httpMethod =
                (Objects.equals(request.method, "GET"))? HttpMethod.GET :
                (Objects.equals(request.method, "PUT"))? HttpMethod.PUT :
                (Objects.equals(request.method, "PATCH"))? HttpMethod.PATCH:
                (Objects.equals(request.method, "DELETE"))? HttpMethod.DELETE : HttpMethod.POST;

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set(HttpHeaders.COOKIE, cookies);

        HttpEntity<String> entity = new HttpEntity<>(request.postData, headers);
        ResponseEntity<String> respEntity = new RestTemplate().exchange(request.url, httpMethod, entity, String.class);

        String tmpCookies = respEntity.getHeaders().getFirst("set-cookie");
        if (tmpCookies != null) cookies = tmpCookies;

        return respEntity.getBody();
    }
}







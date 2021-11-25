package com.example.crud.actuator;

import org.springframework.http.*;

import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import java.util.*;

import static com.example.crud.actuator.ActuatorJsonToHtml.*;


@RestController
@RequestMapping("/api")
public class ActuatorController {

    @GetMapping("/monitor")
    String getActuator(@RequestParam("data") Optional<String> actuatorData) { //,required=false ,defaultValue="Hello World"
        HttpHeaders headers = new HttpHeaders();
        //headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<String> entity = new HttpEntity<>(headers);
        ResponseEntity<String> respEntity = new RestTemplate().exchange("http://localhost/actuator/" + actuatorData.orElse(""), HttpMethod.GET, entity, String.class);
        return getHtmlData(respEntity.getBody());
    }

}







package com.csaw.heapdump;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.web.bind.annotation.*;

import java.sql.SQLException;

@RestController
@RequestMapping(path="/contact")
public class ContactController {

    @Autowired
    private ContactRepository contactRepository;

    @Autowired
    private Environment env;

    @Value("${spring.datasource.username}")
    private String username;

    @Value("${spring.datasource.password}")
    private String password;

    @PostMapping
    public @ResponseBody Contact addNewContact(@RequestBody Contact c) {
        contactRepository.save(c);
        return c;
    }

    @GetMapping
    public @ResponseBody Iterable<Contact> allContacts() {
        System.out.println(username.substring(0, 1));
        System.out.println(password.substring(0, 1));
        return contactRepository.findAll();
    }

    @GetMapping(path="/{id}")
    public @ResponseBody Contact getContact(@PathVariable("id") Integer id) throws Exception {
        throw new SQLException("Failed to connect to " + env.getProperty("spring.datasource.url"));
    }
}

package com.csaw.heapdump;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class Application {

    public static void main(String[] args) throws Exception {
        Class.forName("org.postgresql.Driver");
        SpringApplication.run(Application.class, args);
    }
}
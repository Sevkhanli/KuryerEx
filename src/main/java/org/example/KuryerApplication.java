package org.example;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class KuryerApplication {
    // Sinfin adını layihənizin adı ilə (Kuryer) əlaqələndirmək yaxşı praktikadır

    public static void main(String[] args) {
        // Bu metod bütün Spring Boot komponentlərini yükləyəcək (Tomcat, Beans, Konfiqurasiya)
        SpringApplication.run(KuryerApplication.class, args);
    }
}
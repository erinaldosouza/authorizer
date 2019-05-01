package br.com.tcc.authorizer;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.netflix.eureka.EnableEurekaClient;

@EnableEurekaClient
@SpringBootApplication
public class AuthorizerApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthorizerApplication.class, args);
	}

}

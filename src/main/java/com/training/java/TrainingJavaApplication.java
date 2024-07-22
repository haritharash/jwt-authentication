package com.training.java;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

@SpringBootApplication()
@Configuration
@ComponentScan(basePackages = { "com.training.java", "com.training.config", "com.training.auth",
		"com.training.exception" })
public class TrainingJavaApplication {

	public static void main(String[] args) {
		SpringApplication.run(TrainingJavaApplication.class, args);
	}

}

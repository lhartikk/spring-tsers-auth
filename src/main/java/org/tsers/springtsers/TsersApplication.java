package org.tsers.springtsers;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

@SpringBootApplication
public class TsersApplication {

	public static void main(String[] args) {
		SpringApplication.run(TsersApplication.class, args);
	}

}

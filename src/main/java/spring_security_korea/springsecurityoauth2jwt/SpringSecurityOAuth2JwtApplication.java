package spring_security_korea.springsecurityoauth2jwt;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

@SpringBootApplication
@EnableJpaAuditing
public class SpringSecurityOAuth2JwtApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityOAuth2JwtApplication.class, args);
	}

}

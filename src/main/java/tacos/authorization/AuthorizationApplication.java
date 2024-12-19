package tacos.authorization;

import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;
import tacos.authorization.users.TacoUser;
import tacos.authorization.users.TacoUserRepository;

@SpringBootApplication
public class AuthorizationApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthorizationApplication.class, args);
	}

	@Bean
	ApplicationRunner dataLoader(TacoUserRepository tacoUserRepository,
								 PasswordEncoder encoder) {
		return args -> {
			tacoUserRepository.save(
					new TacoUser("testUser", encoder.encode("111"), "ROLE_ADMIN"));

			tacoUserRepository.save(
					new TacoUser("admin", encoder.encode("password"), "ROLE_ADMIN"));
		};
	}
}

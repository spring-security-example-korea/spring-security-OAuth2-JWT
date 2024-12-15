package spring_security_korea.springsecurityoauth2jwt.config;

import java.util.Arrays;
import java.util.Collections;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import lombok.RequiredArgsConstructor;
import spring_security_korea.springsecurityoauth2jwt.security.oauth2.handler.OAuth2AuthenticationFailureHandler;
import spring_security_korea.springsecurityoauth2jwt.security.oauth2.handler.OAuth2AuthenticationSuccessHandler;
import spring_security_korea.springsecurityoauth2jwt.security.oauth2.service.CustomOAuth2UserService;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

	private final CustomOAuth2UserService customOAuth2UserService;
	private final OAuth2AuthenticationSuccessHandler oAuth2SuccessHandler;
	private final OAuth2AuthenticationFailureHandler oAuth2FailureHandler;

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

		http
			.authorizeHttpRequests(auth -> auth
				.requestMatchers("/api/user/**").hasRole("USER")
				.requestMatchers("/api/admin/**").hasRole("ADMIN")
				.requestMatchers("/login-error").permitAll()
				.anyRequest().authenticated()
			);

		http
			.cors(corsCustomizer -> corsCustomizer.configurationSource(corsConfigurationSource()));

		http
			.csrf(AbstractHttpConfigurer::disable)
			.formLogin(AbstractHttpConfigurer::disable)
			.httpBasic(AbstractHttpConfigurer::disable);

		http
			.oauth2Login(oauth2 -> oauth2
				.userInfoEndpoint(userInfoEndpoint -> userInfoEndpoint
					.userService(customOAuth2UserService))
				.successHandler(oAuth2SuccessHandler)
				.failureHandler(oAuth2FailureHandler));

		return http.build();
	}

	private CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration configuration = new CorsConfiguration();
		configuration.setAllowedOriginPatterns(Collections.singletonList("*"));
		configuration.setAllowedMethods(Collections.singletonList("*"));
		configuration.setAllowCredentials(true);
		configuration.setAllowedHeaders(Collections.singletonList("*"));
		configuration.setExposedHeaders(Arrays.asList("Authorization", "Refresh-Token"));
		configuration.setMaxAge(3600L);

		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);

		return source;
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
}

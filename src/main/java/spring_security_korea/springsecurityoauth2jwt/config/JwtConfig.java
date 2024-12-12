package spring_security_korea.springsecurityoauth2jwt.config;

import io.jsonwebtoken.security.Keys;
import lombok.Getter;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

import java.security.Key;

@Getter
@Configuration
public class JwtConfig {

	private final String secretKey;
	private final Long accessExpiration;
	private final Long refreshExpiration;
	private final String accessCookie;
	private final String refreshCookie;
	private final String redirectUriUser;
	private final Key signingKey;

	public JwtConfig(
		@Value("${jwt.secretKey}") String secretKey,
		@Value("${jwt.access.expiration}") Long accessExpiration,
		@Value("${jwt.refresh.expiration}") Long refreshExpiration,
		@Value("${jwt.access.cookie}") String accessCookie,
		@Value("${jwt.refresh.cookie}") String refreshCookie,
		@Value("${jwt.redirect-uri-user}") String redirectUriUser
	) {
		this.secretKey = secretKey;
		this.accessExpiration = accessExpiration;
		this.refreshExpiration = refreshExpiration;
		this.accessCookie = accessCookie;
		this.refreshCookie = refreshCookie;
		this.redirectUriUser = redirectUriUser;
		this.signingKey = Keys.hmacShaKeyFor(secretKey.getBytes());
	}

	// Constants
	public static final String ACCESS_TOKEN_SUBJECT = "AccessToken";
	public static final String REFRESH_TOKEN_SUBJECT = "RefreshToken";
	public static final String EMAIL_CLAIM = "email";
	public static final String USER_NUMBER = "userNumber";
	public static final String BEARER = "Bearer ";
	public static final String AUTHORIZATION = "Authorization";
}
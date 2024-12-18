package spring_security_korea.springsecurityoauth2jwt.security.jwt.token;

import static spring_security_korea.springsecurityoauth2jwt.config.JwtConfig.*;

import java.nio.charset.StandardCharsets;
import java.time.Instant;

import javax.crypto.SecretKey;

import org.springframework.stereotype.Component;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import spring_security_korea.springsecurityoauth2jwt.config.JwtConfig;

@Component
@RequiredArgsConstructor
public class HmacJwtTokenGeneratorImpl implements JwtTokenGenerator {

	private final JwtConfig jwtConfig;

	@Override
	public String generateAccessToken(String email, String uuid, String role) {
		// 토큰 생성 로직
		return createToken(ACCESS_TOKEN_SUBJECT, jwtConfig.getAccessExpiration(), email, uuid, role);

	}

	@Override
	public String generateRefreshToken() {
		return createToken(REFRESH_TOKEN_SUBJECT, jwtConfig.getRefreshExpiration(), null, null, null);
	}

	private String createToken(String subject, Long expirationPeriod, String email, String uuid, String role) {
		Instant now = Instant.now();
		Instant expirationTime = now.plusSeconds(expirationPeriod);

		// SecretKey 생성 (jwtConfig에서 동일한 방식으로 생성)
		SecretKey secretKey = Keys.hmacShaKeyFor(jwtConfig.getSecretKey().getBytes(StandardCharsets.UTF_8));

		JwtBuilder jwtBuilder = Jwts.builder()
			.claim("sub", subject)
			.claim("exp", expirationTime.getEpochSecond())
			.signWith(secretKey, SignatureAlgorithm.HS256);

		if (email != null) {
			jwtBuilder.claim(EMAIL_CLAIM, email);
		}

		if (uuid != null) {
			jwtBuilder.claim(USER_NUMBER, uuid);
		}

		if (role != null) {
			jwtBuilder.claim(USER_ROLE, role);
		}

		return jwtBuilder.compact();
	}

}

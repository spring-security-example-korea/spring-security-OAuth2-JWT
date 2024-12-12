package spring_security_korea.springsecurityoauth2jwt.security.jwt.token;

import static spring_security_korea.springsecurityoauth2jwt.config.JwtConfig.*;

import java.time.Instant;

import org.springframework.stereotype.Component;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import lombok.RequiredArgsConstructor;
import spring_security_korea.springsecurityoauth2jwt.config.JwtConfig;

@Component
@RequiredArgsConstructor
public class HmacJwtTokenGeneratorImpl implements JwtTokenGenerator {

	private final JwtConfig jwtConfig;

	@Override
	public String generateAccessToken(String email, Long id) {
		// 토큰 생성 로직
		return createToken(ACCESS_TOKEN_SUBJECT, jwtConfig.getAccessExpiration(), email, id);

	}

	@Override
	public String generateRefreshToken() {
		return createToken(REFRESH_TOKEN_SUBJECT, jwtConfig.getRefreshExpiration(), null, null);
	}

	private String createToken(String subject, Long expirationPeriod, String email, Long id){
		Instant now = Instant.now();
		Instant expirationTime = now.plusSeconds(expirationPeriod);


		JwtBuilder jwtBuilder = Jwts.builder()
			.claim("sub",subject)
			.claim("exp", expirationTime.getEpochSecond())
			.signWith(jwtConfig.getSigningKey());

		if (email != null) {
			jwtBuilder.claim(EMAIL_CLAIM, email);
		}

		if (id != null){
			jwtBuilder.claim(USER_NUMBER,id);
		}

		return jwtBuilder.compact();
	}
}

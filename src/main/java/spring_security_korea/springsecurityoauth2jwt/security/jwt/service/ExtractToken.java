package spring_security_korea.springsecurityoauth2jwt.security.jwt.service;

import static spring_security_korea.springsecurityoauth2jwt.config.JwtConfig.*;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Optional;

import javax.crypto.SecretKey;

import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import spring_security_korea.springsecurityoauth2jwt.config.JwtConfig;

@Component
@RequiredArgsConstructor
public class ExtractToken {

	private final JwtConfig jwtConfig;

	public Optional<String> extractTokenCookie(HttpServletRequest request, String tokenName) {
		Cookie[] cookies = request.getCookies();
		if (cookies != null) {
			return Arrays.stream(cookies)
				.filter(cookie -> tokenName.equals(cookie.getName()))
				.findFirst()
				.map(Cookie::getValue);
		}
		return Optional.empty();
	}

	public Optional<String> extractTokenHeader(HttpServletRequest request, String tokenName) {
		return Optional.ofNullable(request.getHeader(tokenName))
			.filter(verifyToken -> verifyToken.startsWith(BEARER))
			.map(verifyToken -> verifyToken.replace(BEARER, ""));
	}

	// 이메일 추출 메서드
	public Optional<String> extractEmail(String token) {
		try {
			Claims claims = parseToken(token);
			return Optional.ofNullable(claims.get("email", String.class));
		} catch (JwtException e) {
			// 토큰이 유효하지 않거나 이메일 클레임이 없을 시 Optional.empty() 반환
			return Optional.empty();
		}
	}

	// 추가적인 클레임 추출 메서드 예시
	public Optional<String> extractUuid(String token) {
		try {
			Claims claims = parseToken(token);
			return Optional.ofNullable(claims.get("uuid", String.class));
		} catch (JwtException e) {
			return Optional.empty();
		}
	}

	private Claims parseToken(String token) throws JwtException {
		SecretKey secretKey = Keys.hmacShaKeyFor(
			jwtConfig.getSecretKey().getBytes(StandardCharsets.UTF_8));
		return Jwts.parserBuilder()
			.setSigningKey(secretKey)
			.build()
			.parseClaimsJws(token)
			.getBody();
	}
}

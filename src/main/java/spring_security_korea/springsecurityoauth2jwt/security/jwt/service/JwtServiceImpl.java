package spring_security_korea.springsecurityoauth2jwt.security.jwt.service;

import static spring_security_korea.springsecurityoauth2jwt.config.JwtConfig.*;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Optional;

import javax.crypto.SecretKey;

import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import spring_security_korea.springsecurityoauth2jwt.config.JwtConfig;
import spring_security_korea.springsecurityoauth2jwt.member.domain.Member;
import spring_security_korea.springsecurityoauth2jwt.member.service.MemberAuthService;
import spring_security_korea.springsecurityoauth2jwt.security.jwt.token.JwtTokenGenerator;
import spring_security_korea.springsecurityoauth2jwt.security.jwt.token.JwtTokenizer;

@Service
@RequiredArgsConstructor
public class JwtServiceImpl implements JwtService {

	private final JwtTokenGenerator hmacJwtTokenGeneratorImpl;
	private final MemberAuthService memberAuthService;
	private final JwtConfig jwtConfig;
	private final ExtractToken extractToken;
	private final JwtTokenizer jwtTokenizer;

	/**
	 * AccessToken 생성 메소드
	 */

	@Override
	public String createAccessToken(String email) {
		Member member = memberAuthService.getMemberByEmail(email);
		return hmacJwtTokenGeneratorImpl.generateAccessToken(member.getEmail(), member.getUuid().toString(),
			member.getRole().getRoleName());
	}

	@Override
	public String createRefreshToken() {
		return hmacJwtTokenGeneratorImpl.generateRefreshToken();
	}

	/**
	 * RefreshToken 추출
	 */
	@Override
	public Optional<String> extractRefreshToken(HttpServletRequest request) {
		return extractToken.extractTokenCookie(request, jwtConfig.getRefreshTokenName());
	}

	/**
	 * AccessToken 추출
	 */
	@Override
	public Optional<String> extractAccessToken(HttpServletRequest request) {
		// "Authorization" 헤더를 확인합니다.
		//String authorizationHeader = request.getHeader(AUTHORIZATION);

		// "Authorization" 헤더가 존재하면, 헤더에서 토큰을 추출합니다.
		//if (authorizationHeader != null && !authorizationHeader.isEmpty()) {
		return extractToken.extractTokenHeader(request, AUTHORIZATION);
		//}

		// "Authorization" 헤더가 존재하지 않으면, 쿠키에서 토큰을 추출합니다.
		//return extractToken.extractTokenCookie(request, jwtConfig.getAccessTokenName());

	}

	@Override
	public void sendToken(HttpServletResponse response, String accessToken, String refreshToken) {
		jwtTokenizer.addAccessTokenCookie(response, accessToken);
		jwtTokenizer.addRefreshTokenCookie(response, refreshToken);
		jwtTokenizer.addAccessRefreshTokenResponseBody(response, accessToken, refreshToken);
	}

	@Override
	public Optional<String> getEmailByToken(String accessToken) {
		return extractToken.extractEmail(accessToken);
	}

	@Override
	public boolean isTokenValid(String token) {
		try {
			// 키 생성
			SecretKey secretKey = Keys.hmacShaKeyFor(
				jwtConfig.getSecretKey().getBytes(StandardCharsets.UTF_8));

			// 토큰 검증 및 파싱
			Claims claims = Jwts.parserBuilder()
				.setSigningKey(secretKey) // 서명 검증 키 설정
				.build()
				.parseClaimsJws(token) // 토큰 파싱 및 검증
				.getBody();

			// 만료 시간 확인
			Date expiration = claims.getExpiration();
			if (expiration != null && expiration.before(new Date())) {

				return false;
			}
			return true;

		} catch (ExpiredJwtException e) {
			return false;
		} catch (JwtException e) {
			return false;
		} catch (Exception e) {
			return false;
		}
	}

	@Override
	public void updateRefreshToken(String email, String refreshToken) {
		Member member = memberAuthService.getMemberByEmail(email);
		member.updateRefreshToken(refreshToken);
		memberAuthService.saveMember(member);
	}

}

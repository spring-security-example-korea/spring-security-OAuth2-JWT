package spring_security_korea.springsecurityoauth2jwt.security.jwt.service;

import java.util.Optional;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public interface JwtService {
	/**
	 * AccessToken 생성 메소드
	 */
	String createAccessToken(String email);

	/**
	 * RefreshToken 생성
	 * RefreshToken은 Claim에 email도 넣지 않으므로 withClaim() X
	 */
	String createRefreshToken();

	/**
	 * 쿠키에서 RefreshToken 추출
	 */
	Optional<String> extractRefreshToken(HttpServletRequest request);

	/**
	 * 쿠키에서 AccessToken 추출
	 */
	Optional<String> extractAccessToken(HttpServletRequest request);

	/**
	 * AccessToken에서 Email 추출
	 * 유효하다면 getClaim()으로 이메일 추출
	 * 유효하지 않다면 빈 Optional 객체 반환
	 */
	Optional<String> getEmailByToken(String accessToken);

	boolean isTokenValid(String token);

	void sendToken(HttpServletResponse response, String accessToken, String refreshToken);

	void updateRefreshToken(String email, String refreshToken);

}

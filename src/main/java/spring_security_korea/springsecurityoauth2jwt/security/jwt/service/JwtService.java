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



}

package spring_security_korea.springsecurityoauth2jwt.security.jwt.token;

import org.springframework.context.annotation.Configuration;

import jakarta.servlet.http.HttpServletResponse;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import spring_security_korea.springsecurityoauth2jwt.config.JwtConfig;

@Configuration
@Getter
@RequiredArgsConstructor
public class JwtTokenizer {

	private final TokenSendManager tokenSendManager;
	private final JwtConfig jwtConfig;

	public void addAccessTokenCookie(HttpServletResponse response, String accessToken) {
		tokenSendManager.addTokenCookie(response, jwtConfig.getAccessTokenName(), accessToken, "/",
			jwtConfig.getAccessExpiration().intValue(), false);
	}

	public void addRefreshTokenCookie(HttpServletResponse response, String refreshToken) {
		tokenSendManager.addTokenCookie(response, jwtConfig.getRefreshTokenName(), refreshToken,
			"/api/v1/refresh/token", jwtConfig.getRefreshExpiration().intValue(), true);
	}

	public void addAccessRefreshTokenResponseBody(HttpServletResponse response, String accessToken,
		String refreshToken) {
		tokenSendManager.addTokenResponseBody(response, accessToken, refreshToken);
	}

}

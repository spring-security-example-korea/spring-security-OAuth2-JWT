package spring_security_korea.springsecurityoauth2jwt.security.oauth2.handler;

import java.io.IOException;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import spring_security_korea.springsecurityoauth2jwt.security.jwt.service.JwtService;
import spring_security_korea.springsecurityoauth2jwt.security.oauth2.PrincipalUser;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

	private final JwtService jwtService;

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
		Authentication authentication) throws IOException, ServletException {

		PrincipalUser oAuth2UserPrincipal = getOAuth2UserPrincipal(authentication);

		if (oAuth2UserPrincipal == null) {
			log.error("Failed to get PrincipalUser from authentication");
			response.sendRedirect("/oauth2-error");
		}

		// todo: JWT
		assert oAuth2UserPrincipal != null;
		loginSuccess(response, oAuth2UserPrincipal);

		log.info("카카오 로그인 성공");
		response.sendRedirect("/login-success");

	}

	private PrincipalUser getOAuth2UserPrincipal(Authentication authentication) {
		Object principal = authentication.getPrincipal();

		if (principal instanceof PrincipalUser) {
			return (PrincipalUser)principal;
		}
		return null;
	}

	private void loginSuccess(HttpServletResponse response, PrincipalUser oAuth2UserPrincipal) throws IOException {
		String email = oAuth2UserPrincipal.getEmail();
		if (email == null || email.isEmpty()) {
			log.error("User email is missing");
			response.sendRedirect("/oauth2-error");
			return;
		}

		try {
			String accessToken = jwtService.createAccessToken(oAuth2UserPrincipal.getEmail());
			String refreshToken = jwtService.createRefreshToken();

			jwtService.sendToken(response, accessToken, refreshToken);
			jwtService.updateRefreshToken(oAuth2UserPrincipal.getEmail(), refreshToken);
		} catch (Exception e) {
			response.sendRedirect("/oauth2-error");
		}

	}
}

package spring_security_korea.springsecurityoauth2jwt.security.jwt.token;

import java.io.IOException;

import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import spring_security_korea.springsecurityoauth2jwt.security.jwt.dto.CeoLoginSuccessRes;

@RequiredArgsConstructor
@Component
@Slf4j
public class TokenSendManager {
	private final ObjectMapper objectMapper;

	public void addTokenCookie(HttpServletResponse response, String name, String value, String path, int maxAge,
		boolean httpOnly) {
		Cookie cookie = new Cookie(name, value);
		cookie.setHttpOnly(httpOnly);
		cookie.setPath(path);
		cookie.setMaxAge(maxAge);
		response.addCookie(cookie);
	}

	public void addTokenResponseBody(HttpServletResponse response, String accessToken, String refreshToken) {

		// Json 응답 생성 및 전송
		response.setContentType("application/json;charset=UTF-8");
		response.setStatus(HttpServletResponse.SC_OK);
		CeoLoginSuccessRes ceoLoginSuccessRes = CeoLoginSuccessRes
			.builder()
			.success(true)
			.message("로그인 성공")
			.accessToken(accessToken)
			.refreshToken(refreshToken)
			.build();

		try {
			String jsonResponse = objectMapper.writeValueAsString(ceoLoginSuccessRes);
			response.getWriter().write(jsonResponse);
			log.info("response 반환" + response);
		} catch (IOException e) {
			log.error("Failed to write response body", e);
		}
	}
}

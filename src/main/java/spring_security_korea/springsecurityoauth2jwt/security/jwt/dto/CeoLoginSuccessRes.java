package spring_security_korea.springsecurityoauth2jwt.security.jwt.dto;

import lombok.Builder;
import lombok.Getter;
import spring_security_korea.springsecurityoauth2jwt.utils.Role;

@Getter
@Builder
public class CeoLoginSuccessRes {
	private boolean success;
	private String message;
	private String accessToken;
	private String refreshToken;
	private Role role;
}

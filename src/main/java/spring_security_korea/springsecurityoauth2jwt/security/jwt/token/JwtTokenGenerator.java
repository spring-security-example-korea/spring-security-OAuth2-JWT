package spring_security_korea.springsecurityoauth2jwt.security.jwt.token;

import java.util.UUID;

import spring_security_korea.springsecurityoauth2jwt.utils.Role;

public interface JwtTokenGenerator {

	String generateAccessToken(String email, String uuid, String role);
	String generateRefreshToken();
}

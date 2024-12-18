package spring_security_korea.springsecurityoauth2jwt.security.jwt.token;

public interface JwtTokenGenerator {

	String generateAccessToken(String email, String uuid, String role);

	String generateRefreshToken();

}

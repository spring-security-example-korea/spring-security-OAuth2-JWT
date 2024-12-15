package spring_security_korea.springsecurityoauth2jwt.security.jwt.filter;

import java.io.IOException;

import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import spring_security_korea.springsecurityoauth2jwt.member.service.MemberAuthService;
import spring_security_korea.springsecurityoauth2jwt.security.jwt.service.JwtService;

@RequiredArgsConstructor
public class JwtAuthenticationProcessingFilter extends OncePerRequestFilter {
	private final JwtService jwtService;

	private final MemberAuthService memberAuthService;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
		FilterChain filterChain) throws ServletException, IOException {

	}
}

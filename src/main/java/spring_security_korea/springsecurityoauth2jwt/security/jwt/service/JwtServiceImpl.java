package spring_security_korea.springsecurityoauth2jwt.security.jwt.service;

import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import spring_security_korea.springsecurityoauth2jwt.member.domain.Member;
import spring_security_korea.springsecurityoauth2jwt.member.service.MemberAuthService;
import spring_security_korea.springsecurityoauth2jwt.security.jwt.token.JwtTokenGenerator;

@Service
@RequiredArgsConstructor
public class JwtServiceImpl implements JwtService {

	private final JwtTokenGenerator hmacJwtTokenGeneratorImpl;
	private final MemberAuthService memberAuthService;

	/**
	 * AccessToken 생성 메소드
	 */

	@Override
	public String createAccessToken(String email) {
		Member member = memberAuthService.getMemberBySocialId(email);
		return hmacJwtTokenGeneratorImpl.generateAccessToken(member.getEmail(), member.getUuid().toString(),
			member.getRole().getRoleName());
	}

	@Override
	public String createRefreshToken() {
		return hmacJwtTokenGeneratorImpl.generateRefreshToken();
	}
}

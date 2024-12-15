package spring_security_korea.springsecurityoauth2jwt.member.service;

import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import spring_security_korea.springsecurityoauth2jwt.member.domain.Member;
import spring_security_korea.springsecurityoauth2jwt.member.repository.MemberRepository;
import spring_security_korea.springsecurityoauth2jwt.security.jwt.repository.RefreshTokenRepository;

@Service
@RequiredArgsConstructor
public class MemberAuthService {

	private MemberRepository memberRepository;
	private RefreshTokenRepository refreshTokenRepository;

	public Member getMemberBySocialId(String socialId){
		return memberRepository.findBySocialId(socialId);
	}

	public Member getMemberByEmail(String email){
		return memberRepository.findByEmail(email);
	}


}

package spring_security_korea.springsecurityoauth2jwt.member.service;

import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import spring_security_korea.springsecurityoauth2jwt.exception.OAuth2AuthenticationProcessingException;
import spring_security_korea.springsecurityoauth2jwt.member.domain.Member;
import spring_security_korea.springsecurityoauth2jwt.member.repository.MemberRepository;

@Service
@RequiredArgsConstructor
public class MemberAuthService {

	private MemberRepository memberRepository;

	public Member getMemberBySocialId(String socialId) {
		return memberRepository.findBySocialId(socialId).orElseThrow(
			() -> new OAuth2AuthenticationProcessingException("유저를 찾을 수 없습니다.")
		);
	}

	public Member getMemberByEmail(String email) {
		return memberRepository.findByEmail(email).orElseThrow(
			() -> new OAuth2AuthenticationProcessingException("유저를 찾을 수 없습니다.")
		);
	}

}

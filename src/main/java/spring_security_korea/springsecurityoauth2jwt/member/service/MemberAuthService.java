package spring_security_korea.springsecurityoauth2jwt.member.service;

import java.util.Optional;

import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import spring_security_korea.springsecurityoauth2jwt.exception.OAuth2AuthenticationProcessingException;
import spring_security_korea.springsecurityoauth2jwt.member.domain.Member;
import spring_security_korea.springsecurityoauth2jwt.member.repository.MemberRepository;

@Service
@RequiredArgsConstructor
public class MemberAuthService {

	private final MemberRepository memberRepository;

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

	public Optional<Member> getMemberByRefreshToken(String refreshToken) {
		return memberRepository.findByRefreshToken(refreshToken);
	}

	public void updateRefreshToken(Member member, String reIssuedRefreshToken) {
		member.updateRefreshToken(reIssuedRefreshToken);
		memberRepository.saveAndFlush(member);
	}

	public Optional<Member> findOptionalMemberByEmail(String email) {
		return memberRepository.findByEmail(email);
	}

	public void saveMember(Member member) {
		memberRepository.save(member);
	}
}

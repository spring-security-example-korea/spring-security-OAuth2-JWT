package spring_security_korea.springsecurityoauth2jwt.security.oauth2.service;

import java.util.Optional;

import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import lombok.RequiredArgsConstructor;
import spring_security_korea.springsecurityoauth2jwt.exception.OAuth2AuthenticationProcessingException;
import spring_security_korea.springsecurityoauth2jwt.member.domain.Member;
import spring_security_korea.springsecurityoauth2jwt.member.repository.MemberRepository;
import spring_security_korea.springsecurityoauth2jwt.security.oauth2.OAuth2ProviderFactory;
import spring_security_korea.springsecurityoauth2jwt.security.oauth2.OAuth2ProviderUser;
import spring_security_korea.springsecurityoauth2jwt.security.oauth2.PrincipalUser;
import spring_security_korea.springsecurityoauth2jwt.utils.Role;

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

	private final MemberRepository memberRepository;

	@Override
	public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

		OAuth2User oAuth2User = super.loadUser(userRequest);

		try {
			return processOAuth2User(userRequest, oAuth2User);
		} catch (AuthenticationException ex) {
			throw ex;
		} catch (Exception ex) {
			throw new InternalAuthenticationServiceException(ex.getMessage(), ex.getCause());
		}

	}

	private OAuth2User processOAuth2User(OAuth2UserRequest userRequest, OAuth2User oAuth2User) {
		ClientRegistration clientRegistration = userRequest.getClientRegistration();

		OAuth2ProviderUser oAuth2UserInfo = OAuth2ProviderFactory.getOAuth2UserInfo(clientRegistration, oAuth2User);

		Optional<Member> memberOpt = memberRepository.findBySocialId(oAuth2UserInfo.getSocialId());

		if (memberOpt.isEmpty()) {
			register(oAuth2UserInfo);
		}

		if (!StringUtils.hasText(oAuth2UserInfo.getSocialId())) {
			throw new OAuth2AuthenticationProcessingException("id not found from OAuth2 provider");
		}

		return new PrincipalUser(oAuth2UserInfo);
	}

	private void register(OAuth2ProviderUser userInfo) {
		Member member = Member.builder()
			.email(userInfo.getEmail())
			.provider(userInfo.getProvider())
			.socialId(userInfo.getSocialId())
			.role(Role.ROLE_USER)
			.profileImage(userInfo.getProfileImage())
			.username(userInfo.getUsername())
			.build();

		memberRepository.save(member);
	}
}

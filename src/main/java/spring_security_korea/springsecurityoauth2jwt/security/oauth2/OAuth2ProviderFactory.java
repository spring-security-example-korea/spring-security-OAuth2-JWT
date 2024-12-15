package spring_security_korea.springsecurityoauth2jwt.security.oauth2;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.user.OAuth2User;

import spring_security_korea.springsecurityoauth2jwt.exception.OAuth2AuthenticationProcessingException;
import spring_security_korea.springsecurityoauth2jwt.security.oauth2.kakao.KakaoUser;

public class OAuth2ProviderFactory {
	public static OAuth2ProviderUser getOAuth2UserInfo(ClientRegistration clientRegistration, OAuth2User oAuth2User) {

		String registrationId = clientRegistration.getRegistrationId();

		if (registrationId.equals(OAuth2Provider.KAKAO.getRegistrationId())) {
			return new KakaoUser(oAuth2User, clientRegistration);
		} else {
			throw new OAuth2AuthenticationProcessingException(registrationId + "로그인은 지원되지 않습니다.");
		}
	}
}

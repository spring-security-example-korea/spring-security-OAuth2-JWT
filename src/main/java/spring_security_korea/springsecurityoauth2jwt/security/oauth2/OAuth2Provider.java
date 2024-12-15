package spring_security_korea.springsecurityoauth2jwt.security.oauth2;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum OAuth2Provider {
	KAKAO("kakao");

	private final String registrationId;
}

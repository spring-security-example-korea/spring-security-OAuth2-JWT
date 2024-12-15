package spring_security_korea.springsecurityoauth2jwt.security.oauth2;

import java.util.Collection;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;

public record PrincipalUser(ProviderUser providerUser) implements UserDetails, OidcUser, OAuth2User {
	@Override
	public String getName() {
		return providerUser.getUsername();
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return providerUser.getAuthorities();
	}

	@Override
	public String getPassword() {
		return null;
	}

	@Override
	public String getUsername() {
		return providerUser.getUsername();
	}

	@Override
	public Map<String, Object> getClaims() {
		return null;
	}

	@Override
	public OidcUserInfo getUserInfo() {
		return null;
	}

	@Override
	public OidcIdToken getIdToken() {
		return null;
	}

	@Override
	public Map<String, Object> getAttributes() {
		return providerUser.getAttributes();
	}
}

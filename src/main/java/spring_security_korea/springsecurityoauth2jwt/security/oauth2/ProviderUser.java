package spring_security_korea.springsecurityoauth2jwt.security.oauth2;

import java.util.List;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;

public interface ProviderUser {

	public String getSocialId();

	public String getUsername();

	public String getEmail();

	public String getProvider();

	public String getProfileImage();

	public List<? extends GrantedAuthority> getAuthorities();

	public Map<String, Object> getAttributes();
}

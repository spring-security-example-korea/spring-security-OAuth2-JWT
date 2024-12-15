package spring_security_korea.springsecurityoauth2jwt.utils;

import lombok.Getter;

@Getter
public enum Role {
	ROLE_ADMIN("ROLE_ADMIN"),
	ROLE_USER("ROLE_USER");

	private final String roleName;

	Role(String role) {
		this.roleName = role;
	}
}

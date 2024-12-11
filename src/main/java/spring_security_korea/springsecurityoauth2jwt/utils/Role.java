package spring_security_korea.springsecurityoauth2jwt.utils;

import lombok.Getter;

@Getter
public enum Role {
    ADMIN("ROLE_ADMIN"),
    USER("ROLE_USER");

    private final String roleName;

    Role(String role) {
        this.roleName = role;
    }
}

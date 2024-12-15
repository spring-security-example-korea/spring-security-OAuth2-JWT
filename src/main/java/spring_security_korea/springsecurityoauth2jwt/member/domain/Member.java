package spring_security_korea.springsecurityoauth2jwt.member.domain;

import java.time.LocalDateTime;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import spring_security_korea.springsecurityoauth2jwt.utils.BaseEntity;
import spring_security_korea.springsecurityoauth2jwt.utils.Role;


import java.time.LocalDateTime;
import java.util.UUID;


@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Member extends BaseEntity {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "member_id")
	private Long id;

	private String username;

	private String password;

	private String email;

	private String profileImage;

	private String provider;

	private String socialId;

	@Enumerated(EnumType.STRING)
	private Role role;

	private boolean softDelete;

	private LocalDateTime softDeleteTime;


    @Column(nullable = false, unique = true, updatable = false)
    private UUID uuid;


    
	private String refreshToken;

	@Builder
	public Member(String username, String password, String email, String profileImage, String provider, String socialId,
		Role role) {
		this.username = username;
		this.password = password;
		this.email = email;
		this.profileImage = profileImage;
		this.provider = provider;
		this.socialId = socialId;
		this.role = role;
	}


	public void softDelete() {
		this.softDelete = true;
		softDeleteTime = LocalDateTime.now();
	}


    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public void regenerateUUID() {
        this.uuid = UUID.randomUUID();
    }


}

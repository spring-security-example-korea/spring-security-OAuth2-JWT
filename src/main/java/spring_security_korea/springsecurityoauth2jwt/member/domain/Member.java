package spring_security_korea.springsecurityoauth2jwt.member.domain;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import spring_security_korea.springsecurityoauth2jwt.utils.BaseEntity;
import spring_security_korea.springsecurityoauth2jwt.utils.Role;

import java.time.LocalDateTime;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Member extends BaseEntity {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "member_id")
    private Long id;

    private String username;

    private String password;

    private String email;

    private String profileImage;

    private String socialId;

    private Role role;

    private boolean softDelete;

    private LocalDateTime softDeleteTime;

    private String refreshToken;


    @Builder
    public Member(String username, String password, String email, String profileImage, String socialId, Role role) {
        this.username = username;
        this.password = password;
        this.email = email;
        this.profileImage = profileImage;
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
}

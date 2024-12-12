package spring_security_korea.springsecurityoauth2jwt.member.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import spring_security_korea.springsecurityoauth2jwt.member.domain.Member;

public interface MemberRepository extends JpaRepository<Member, Long> {

	Optional<Member> findByEmail(String email);

	Optional<Member> findBySocialId(String socialId);
}

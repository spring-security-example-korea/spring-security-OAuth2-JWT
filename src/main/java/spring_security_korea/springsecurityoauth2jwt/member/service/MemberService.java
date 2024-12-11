package spring_security_korea.springsecurityoauth2jwt.member.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import spring_security_korea.springsecurityoauth2jwt.member.repository.MemberRepository;

@Service
@RequiredArgsConstructor
public class MemberService {

    private final MemberRepository memberRepository;
}

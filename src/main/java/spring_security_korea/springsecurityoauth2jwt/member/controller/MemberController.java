package spring_security_korea.springsecurityoauth2jwt.member.controller;

import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;
import spring_security_korea.springsecurityoauth2jwt.member.service.MemberService;

@RestController
@RequiredArgsConstructor

public class MemberController {

	private final MemberService memberService;
}

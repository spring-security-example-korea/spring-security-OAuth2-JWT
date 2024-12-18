package spring_security_korea.springsecurityoauth2jwt.security.jwt.filter;

import java.io.IOException;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import spring_security_korea.springsecurityoauth2jwt.config.JwtConfig;
import spring_security_korea.springsecurityoauth2jwt.member.domain.Member;
import spring_security_korea.springsecurityoauth2jwt.member.service.MemberAuthService;
import spring_security_korea.springsecurityoauth2jwt.security.jwt.service.JwtService;

@RequiredArgsConstructor
public class JwtAuthenticationProcessingFilter extends OncePerRequestFilter {
	private final JwtService jwtService;

	private final MemberAuthService memberAuthService;
	private final JwtConfig jwtConfig;
	private GrantedAuthoritiesMapper authoritiesMapper = new NullAuthoritiesMapper();

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
		FilterChain filterChain) throws ServletException, IOException {

		if (request.getRequestURI().equals(JwtConfig.NO_CHECK_URL)) {
			filterChain.doFilter(request, response);
			return;
		}

		String refreshToken = jwtService.extractRefreshToken(request)
			.filter(jwtService::isTokenValid)
			.orElse(null);

		// 리프레시 토큰이 요청 헤더에 존재했다면, 사용자가 AccessToken이 만료되어서
		// RefreshToken까지 보낸 것이므로 리프레시 토큰이 DB의 리프레시 토큰과 일치하는지 판단 후,
		// 일치한다면 AccessToken을 재발급해준다.
		if (refreshToken != null) {
			checkRefreshTokenAndReIssueAccessToken(response, refreshToken);
			return; // RefreshToken을 보낸 경우에는 AccessToken을 재발급 하고 인증 처리는 하지 않게 하기위해 바로 return으로 필터 진행 막기
		}

		// RefreshToken이 없거나 유효하지 않다면, AccessToken을 검사하고 인증을 처리하는 로직 수행
		// AccessToken이 없거나 유효하지 않다면, 인증 객체가 담기지 않은 상태로 다음 필터로 넘어가기 때문에 403 에러 발생
		// AccessToken이 유효하다면, 인증 객체가 담긴 상태로 다음 필터로 넘어가기 때문에 인증 성공
		if (refreshToken == null) {
			checkAccessTokenAndAuthentication(request, response, filterChain);
		}

	}

	/**
	 *  [리프레시 토큰으로 유저 정보 찾기 & 액세스 토큰/리프레시 토큰 재발급 메소드]
	 *  파라미터로 들어온 헤더에서 추출한 리프레시 토큰으로 DB에서 유저를 찾고, 해당 유저가 있다면
	 *  JwtService.createAccessToken()으로 AccessToken 생성,
	 *  reIssueRefreshToken()로 리프레시 토큰 재발급 & DB에 리프레시 토큰 업데이트 메소드 호출
	 *  그 후 JwtService.sendAccessTokenAndRefreshToken()으로 응답 헤더에 보내기
	 */
	public void checkRefreshTokenAndReIssueAccessToken(HttpServletResponse response, String refreshToken) {
		memberAuthService.getMemberByRefreshToken(refreshToken)
			.ifPresent(member -> {
				String reIssuedRefreshToken = reIssueRefreshToken(member);
				jwtService.sendToken(response, jwtService.createAccessToken(member.getEmail()),
					reIssuedRefreshToken);
			});
	}

	/**
	 * [리프레시 토큰 재발급 & DB에 리프레시 토큰 업데이트 메소드]
	 * jwtService.createRefreshToken()으로 리프레시 토큰 재발급 후
	 * DB에 재발급한 리프레시 토큰 업데이트 후 Flush
	 */
	private String reIssueRefreshToken(Member member) {
		String reIssuedRefreshToken = jwtService.createRefreshToken();
		memberAuthService.updateRefreshToken(member, reIssuedRefreshToken);
		return reIssuedRefreshToken;
	}

	/**
	 * [액세스 토큰 체크 & 인증 처리 메소드]
	 * request에서 extractAccessToken()으로 액세스 토큰 추출 후, isTokenValid()로 유효한 토큰인지 검증
	 * 유효한 토큰이면, 액세스 토큰에서 extractEmail로 Email을 추출한 후 findByEmail()로 해당 이메일을 사용하는 유저 객체 반환
	 * 그 유저 객체를 saveAuthentication()으로 인증 처리하여
	 * 인증 허가 처리된 객체를 SecurityContextHolder에 담기
	 * 그 후 다음 인증 필터로 진행
	 */
	public void checkAccessTokenAndAuthentication(HttpServletRequest request, HttpServletResponse response,
		FilterChain filterChain) throws ServletException, IOException {

		jwtService.extractAccessToken(request)
			.filter(jwtService::isTokenValid)
			.ifPresent(accessToken -> jwtService.getEmailByToken(accessToken)
				.ifPresent(email -> memberAuthService.findOptionalMemberByEmail(email)
					.ifPresent(this::saveAuthentication)));

		filterChain.doFilter(request, response);
	}

	/**
	 * [인증 허가 메소드]
	 * 파라미터의 유저 : 우리가 만든 회원 객체 / 빌더의 유저 : UserDetails의 User 객체
	 *
	 * new UsernamePasswordAuthenticationToken()로 인증 객체인 Authentication 객체 생성
	 * UsernamePasswordAuthenticationToken의 파라미터
	 * 1. 위에서 만든 UserDetailsUser 객체 (유저 정보)
	 * 2. credential(보통 비밀번호로, 인증 시에는 보통 null로 제거)
	 * 3. Collection < ? extends GrantedAuthority>로,
	 * UserDetails의 User 객체 안에 Set<GrantedAuthority> authorities이 있어서 getter로 호출한 후에,
	 * new NullAuthoritiesMapper()로 GrantedAuthoritiesMapper 객체를 생성하고 mapAuthorities()에 담기
	 *
	 * SecurityContextHolder.getContext()로 SecurityContext를 꺼낸 후,
	 * setAuthentication()을 이용하여 위에서 만든 Authentication 객체에 대한 인증 허가 처리
	 */
	public void saveAuthentication(Member member) {
		String password = member.getPassword();
		if (password == null) { // 소셜 로그인 유저의 비밀번호 임의로 설정 하여 소셜 로그인 유저도 인증 되도록 설정
			password = "test_password";
		}

		UserDetails userDetailsUser = org.springframework.security.core.userdetails.User.builder()
			.username(member.getEmail())
			.password(password)
			.roles(member.getRole().name())
			.build();

		Authentication authentication =
			new UsernamePasswordAuthenticationToken(userDetailsUser, null,
				authoritiesMapper.mapAuthorities(userDetailsUser.getAuthorities()));

		SecurityContextHolder.getContext().setAuthentication(authentication);
	}
}

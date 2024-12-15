package spring_security_korea.springsecurityoauth2jwt.security.jwt.repository;

import java.util.Optional;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RefreshTokenRepository extends CrudRepository<RefreshToken, String> {

	Optional<RefreshToken> findByRefreshToken(String refreshToken);

}

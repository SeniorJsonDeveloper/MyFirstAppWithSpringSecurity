package web.testsecurity.exception.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import web.testsecurity.UserEntity;

import java.util.Optional;

public interface UserRepository extends JpaRepository<UserEntity,Long> {
    Optional<UserEntity> findByUsername(String username);
    Boolean existsByUsername(String username);
    

}

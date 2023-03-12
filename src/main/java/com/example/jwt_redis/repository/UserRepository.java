package com.example.jwt_redis.repository;


import com.example.jwt_redis.entity.User;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    @EntityGraph(attributePaths = "authorities") // 쿼리가 수행될 때 Lazy조회가 아니라 Eager 조회로 authorities 정보를 같이 가져오게 된다.
    Optional<User> findOneWithAuthoritiesByUsername(String username);
    // username을 기준으로 User정보를 가져올 때 권한 정보도 같이 가져온다.
}


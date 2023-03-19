package com.example.jwt_redis.service;

import com.example.jwt_redis.dto.UserDto;
import com.example.jwt_redis.entity.Authority;
import com.example.jwt_redis.entity.User;
import com.example.jwt_redis.repository.UserRepository;
import com.example.jwt_redis.util.SecurityUtil;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;
import java.util.Optional;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, BCryptPasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
    public User signup(UserDto userDto) {
        if (userRepository.findOneWithAuthoritiesByUsername(userDto.getUsername()).orElse(null) != null) {
            throw new RuntimeException("이미 가입된 유저 입니다.");
        }

        // 중요한점은 signup메서드를 통해 가입한 회원은 USER ROLE을 가지고 있고
        // data.sql에서 자동 생성되는 admin 계정은 USER, ADMIN ROLE을 가지고 있다.
        // 이 차이를 통한 권한 부분을 테스트하자
        Authority authority = Authority.builder()
                .authorityName("ROLE_USER")
                .build();

        User user = User.builder()
                .username(userDto.getUsername())
                .password(passwordEncoder.encode(userDto.getPassword()))
                .nickname(userDto.getNickname())
                .authorities(Collections.singleton(authority))
                .activated(true)
                .build();

        return userRepository.save(user);
    }

    // username을 기준으로 유저와 권한 정보를 가져온다.
    @Transactional(readOnly = true)
    public Optional<User> getUserWithAuthorities(String username) {
        return userRepository.findOneWithAuthoritiesByUsername(username);
    }

    // 현재 SecurityContext에 저장된 username에 해당하는 유저와 권한 정보를 가져온다
    @Transactional(readOnly = true)
    public Optional<User> getMyUserWithAuthorities() {
        return SecurityUtil.getCurrentUsername().flatMap(userRepository::findOneWithAuthoritiesByUsername);
    }
}

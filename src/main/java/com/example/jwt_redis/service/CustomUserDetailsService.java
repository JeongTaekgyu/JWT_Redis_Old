package com.example.jwt_redis.service;

import com.example.jwt_redis.repository.UserRepository;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    @Transactional(readOnly = true)
    // UserDetailsService의 loadUserByUsername를 오버라이드해서 로그인시에 db에서 유저정보와 권한정보를 가져오게 된다.
    // 해당정보를 기반으로 userdetails.User 객체를 생성해서 반환한다.
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findOneWithAuthoritiesByUsername(username)
                .map(user -> createUser(username, user))
                .orElseThrow(() -> new UsernameNotFoundException(username + " -> 해당 유저를 찾을 수 없습니다."));
    }

    private User createUser(String username, com.example.jwt_redis.entity.User user) {
        // db에서 가져온 정보를 기준으로 그 user가 활성화 상태라면
        if (!user.isActivated()) {
            throw new RuntimeException(username + " -> 활성화되어 있지 않습니다.");
        }
        List<GrantedAuthority> grantedAuthorities = user.getAuthorities().stream()
                .map(authority -> new SimpleGrantedAuthority(authority.getAuthorityName()))
                .collect(Collectors.toList());
        // username, password, grantedAuthorities(유저의 권한정보)를 가지고 User객체를 반환한다
        return new User(user.getUsername(), user.getPassword(), grantedAuthorities);
    }
}

package com.example.jwt_redis.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SecurityException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

@Slf4j
@Component
// 토큰의 생성, 유효성 검증 등을 담당한다
public class TokenProvider implements InitializingBean {

    private static final String AUTHORITIES_KEY = "auth";

    private final String secret;
    private final long tokenValiditiyInMilliseconds;

    private Key key;

    public TokenProvider(
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.token-validity-in-seconds}") long tokenValiditiyInMilliseconds) {
        this.secret = secret;
        this.tokenValiditiyInMilliseconds = tokenValiditiyInMilliseconds * 1000;
    }

    // InitializingBean을 implements해서 afterPropertiesSet을 Override한 이유는
    // Bean이 생성이 되고(@Component로 빈 생성) 의존성 주입을 받은 후에 주입받은 secret값을
    // Base64 Decode해서 key변수에 할당하기 위해서이다.
    @Override
    public void afterPropertiesSet() throws Exception {
        byte[] keyBytes = Decoders.BASE64.decode(secret);
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

    // Authentication객체의 권한정보를 이용해서 토큰을 생성하는 createToken 메서드 추가
    public String createToken(Authentication authentication) {
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        // yml에 설정한 토큰의 expired타임을 설정한다.
        long now = new Date().getTime();
        Date validity = new Date(now + this.tokenValiditiyInMilliseconds);

        return Jwts.builder() // jwt 토큰을 생성해서 return한다.
                .setSubject(authentication.getName())
                .claim(AUTHORITIES_KEY, authorities)
                .signWith(key, SignatureAlgorithm.HS512)
                .setExpiration(validity)
                .compact();
    }

    // Token에 담겨있는 정보를 이용해 Authentication 객체를 리턴하는 메서드 생성
    public Authentication getAuthentication(String token) {
        // token으로 cliams를 만든다.
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();

        // Claim에서 권한 정보들을 빼준다.
        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

        // authorities(권한 정보)를 이용해 User 객체를 만든다.
        User principal = new User(claims.getSubject(), "", authorities);

        // User객체, token, authorities(권한정보)를 이용해서 Authentication 객체를 반환
        return new UsernamePasswordAuthenticationToken(principal, token, authorities);
    }

    // 토큰의 유효성 검사를 수행하는 메서드
    public boolean validateToken(String token) {
        // 토큰을 파싱하고 발생하는 익셉션을 캐치해서 문제가 있으면 false 없으면 true를 반환한다.
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (SecurityException | MalformedJwtException e) {
            log.error("잘못된 jwt 서명입니다.");
        } catch (ExpiredJwtException e) {
            log.error("만료된 jwt 토큰입니다.");
        } catch (UnsupportedJwtException e) {
            log.error("지원되지 않는 jwt 토큰입니다.");
        } catch (IllegalArgumentException e) {
            log.error("jwt 토큰 값이 잘못되었습니다.");
        }
        return false;
    }
}

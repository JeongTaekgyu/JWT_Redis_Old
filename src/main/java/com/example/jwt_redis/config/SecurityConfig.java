package com.example.jwt_redis.config;

import com.example.jwt_redis.jwt.JwtAccessDeniedHandler;
import com.example.jwt_redis.jwt.JwtAuthenticationEntryPoint;
import com.example.jwt_redis.jwt.JwtSecurityConfig;
import com.example.jwt_redis.jwt.TokenProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true) // @PreAuthorize 어노테이션을 메서드 단위로 추가하기 위해 적용
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final TokenProvider tokenProvider;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;

    // 만들어준 클래스를 주입받는다.
    public SecurityConfig(TokenProvider tokenProvider, JwtAccessDeniedHandler jwtAccessDeniedHandler, JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint) {
        this.tokenProvider = tokenProvider;
        this.jwtAccessDeniedHandler = jwtAccessDeniedHandler;
        this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // h2-console 하위 모든 요청들과 파비콘 관련 요청은 Spring Security 로직을 수행하지 않도록
    // configure 메소드를 오버라이드 하여 내용을 추가해 준다.
    @Override
    public void configure(WebSecurity web){
        web
                .ignoring()
                .antMatchers(
                        "/h2-console/**"
                        ,"/favicon.ico"
                );
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable() // 내가 만든 토큰을 사용하기 때문에 csrf설정은 disable로 한다.

                .exceptionHandling() // exceptionHandling할 때 내가 만든 클래스들을 추가한다.
                .authenticationEntryPoint(jwtAuthenticationEntryPoint) // 인증되지 않은 사용자가 보호된 리소스에 액세스하려고 할 때 호출
                .accessDeniedHandler(jwtAccessDeniedHandler) // 인증된 사용자가 리소스에 액세스할 권한이 없는 경우 호출

                .and() // h2-console을 위한 설정 추가
                .headers()
                .frameOptions()
                .sameOrigin()

                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 세션을 사용하지 않아서 세션 설정을 STATELESS로 함

                .and() // 로그인 api, 회원가입 api는 토큰이 없는 상태에서 요청이 들어와서 모두 permitAll()설정함
                .authorizeRequests() // HttpServletRequest를 사용하는 요청들에 대한 접근제한을 설정하겠다는 의미이다.
                .antMatchers("/api/hello").permitAll() // 해당 api에 대한 요청을 인증없이 접근을 허용하겠다.
                .antMatchers("/api/authenticate").permitAll()
                .antMatchers("/api/signup").permitAll()
//                .antMatchers("/api/redisTest").permitAll()
                .antMatchers("/api/redisTest/**").permitAll()
                .anyRequest().authenticated() // 나머지 요청들은 모두 인정되어야 한다.

                .and()
                .apply(new JwtSecurityConfig(tokenProvider));
    }
}

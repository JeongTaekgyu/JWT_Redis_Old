package com.example.jwt_redis.jwt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
//import java.util.logging.Logger;

// JWT를 위한 커스텀 필터를 만들기 위한 JwtFilter클래스
public class JwtFilter extends GenericFilterBean {

    private static final Logger logger = LoggerFactory.getLogger(JwtFilter.class);
    public static final String AUTHORIZATION_HEADER = "Authorization";
    private TokenProvider tokenProvider;
    public JwtFilter(TokenProvider tokenProvider) {
        this.tokenProvider = tokenProvider;
    }

    // 실제 필터링 로직
    // doFilter는 토큰의 인증정보를 현재 실행중인 SecurityContext에 저장하는 역할을 수행한다.
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;

        String jwt = this.resolveToken(httpServletRequest); 
        String requestURI = httpServletRequest.getRequestURI();

        // resolveToken으로 받아온 token으로 유효성 검증을 하고 정상 토큰이면 SecurityContext에 저장
        if (StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt)) {
            // 토큰이 정상이면 Authentication 객체를 받아와서
            Authentication authentication = tokenProvider.getAuthentication(jwt);
            // SecurityContextHolder에 set한다.
            SecurityContextHolder.getContext().setAuthentication(authentication);
            logger.debug("Security Context 에 '{}' 인증 정보를 저장했습니다. uri: {}", authentication.getName(), requestURI);
        } else {
            logger.error("유효한 토큰 정보가 없습니다. uri: {}", requestURI);
        }

        chain.doFilter(request, response);
    }

    // Request Header에서 토큰정보를 꺼내오기 위한 resolveToken 메서드 추가
    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(AUTHORIZATION_HEADER);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}

package com.example.jwt_redis.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.*;

import javax.persistence.*;
import java.util.Set;


@Entity // database 테이블과 1:1 매핑되는 객체
@Table(name = "user")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @JsonIgnore
    @Column(name = "user_id")
    private Long userId;

    @Column(name = "username", length = 50, unique = true)
    private String username;

    @JsonIgnore
    @Column(name = "password", length = 100)
    private String password;

    @Column(name = "nickname", length = 50)
    private String nickname;

    @JsonIgnore
    @Column(name = "activated")
    private boolean activated;

    // User 객체와 권한객체의 다대다 관계를, 일대다, 다대일 관계의 조인 테이블로 정의함.
    // user_authority 라는 중간 테이블이 생성됨
    // 이 테이블은 user_id 컬럼과 authority_name 컬럼을 가지고 있음.
    // user_id 컬럼은 User클래스의 기본키(PK)와 외래키(FK)로 매핑되고, authority_name 컬럼은 Authority 클래스의 기본키(PK)와 외래키(FK)로 매핑됨
    @ManyToMany
    @JoinTable(
            name = "user_authority",
            joinColumns = {@JoinColumn(name = "user_id", referencedColumnName = "user_id")},
            inverseJoinColumns = {@JoinColumn(name = "authority_name", referencedColumnName = "authority_name")}
    )
    private Set<Authority> authorities;
}


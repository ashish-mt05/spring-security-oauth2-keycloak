package com.wstutorial.oauth2.resourceserver;

import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

@EnableWebSecurity
//@EnableWebSecurity ist not necessary. Spring Security is on the classpath,
// hence EnableWebSecurity will be added automatically
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    String jwkSetUri = "http://localhost:8090/auth/realms/wstutorial/protocol/openid-connect/certs";

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests(authorizeRequests -> authorizeRequests
                .antMatchers(HttpMethod.GET, "/protected/**").hasAuthority("admin")
                .antMatchers(HttpMethod.GET, "/admin/**").hasAuthority("user")
                        .anyRequest().authenticated()).oauth2ResourceServer(OAuth2ResourceServerConfigurer::opaqueToken()
                .anyRequest().authenticated()).oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
    }

    @Bean
    JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withJwkSetUri(this.jwkSetUri).build();
    }
}

package com.springsecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

//@Configuration
public class SecurityConfig1 extends WebSecurityConfigurerAdapter {

    // 注入 PasswordEncoder 类到 spring 容器中
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //定义了哪些URL路径应该被拦截
        http
                .formLogin() // 表单登录
                    .and()
                .authorizeRequests() // 认证配置
                    .anyRequest() // 任何请求
                    .authenticated(); // 都需要身份验证
    }

    //第二种方法：在配置类中，配置 用户名 和 密码
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //在内存中配置一个用户
        BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
        String password = bCryptPasswordEncoder.encode("123");
        auth.inMemoryAuthentication().withUser("lucy").password(password).roles("admin");
    }
}

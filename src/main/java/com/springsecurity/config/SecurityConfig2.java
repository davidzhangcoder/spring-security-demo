package com.springsecurity.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

//1.formlogin
//2.authorizeRequests
//3.配置没权限访问，跳转到自定义页面
//4.logout
//5.@Secured
//6.@PreAuthorize
//7.configure(HttpSecurity http)
//8.configure(AuthenticationManagerBuilder auth)
//9.UserDetailsService

@Configuration
@EnableGlobalMethodSecurity(securedEnabled=true, prePostEnabled = true) //开启@Secured注解功能, 开启 Pre 和 Post 注解功能
public class SecurityConfig2 extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        //定义了哪些URL路径应该被拦截
        http
                //formLogin()对应表单认证相关的配置
                .formLogin() // 表单登录
                    .loginPage("/login.html")
                    .loginProcessingUrl("/login") // 设置哪个是登录的 url。
                    //.defaultSuccessUrl("/loginsuccess") // 登录成功之后跳转到哪个 url
                    .defaultSuccessUrl("/loginsuccess.html") // 登录成功之后跳转到哪个 url
                    .failureUrl("/loginfail")
                    //.failureForwardUrl("/loginfail")
                    .permitAll() //必须在这用 .permitAll()，或是下面的.antMatchers()中加入"/login.html"，不然login.html无法显示
                    .and()
                //authorizeRequests()配置路径拦截，表明路径访问所对应的权限，角色，认证信息
                .authorizeRequests() // 认证配置
                    .antMatchers( "/hello", "/login.html").permitAll()
                    .antMatchers("/findAll").hasAuthority("admin")
                    .antMatchers("/findAll").hasRole("managerrole")
                    .antMatchers("/find").access("hasRole('managerrole') or hasAuthority('sales')") //配置 或者有managerrole 角色 或者有 sales 权限
                    //.antMatchers("/find").hasAuthority("sales")
                    //.antMatchers("/find").hasRole("managerrole")
                    .anyRequest() // 任何请求
                    .authenticated(); // 都需要身份验证

        //配置没权限访问，跳转到自定义页面
        http.exceptionHandling().accessDeniedPage("/unauth.html");

        //配置logout
        http.logout().logoutUrl("/logout").logoutSuccessUrl("/logedout").permitAll();

        // 关闭 csrf
        http.csrf().disable();
    }


    //第三种方法：通过 UserDetailsService 返回用户名和密码 （ 即通过数据库查询得到用户名和密码 ）
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder( passwordEncoder() );
    }

    // 注入 PasswordEncoder 类到 spring 容器中
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

}

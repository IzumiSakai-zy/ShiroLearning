package com.config;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@EnableWebSecurity
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {
    //授权
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //按照角色授权
        http.authorizeRequests()
                .antMatchers("/","/index.html").permitAll()
                .antMatchers("/level1/**").hasRole("vip1")
                .antMatchers("/level2/**").hasRole("vip2")
                .antMatchers("/level3/**").hasRole("vip3");
        //默认跳到登录页面
        http.formLogin()
                .loginPage("/toLogin")
                .loginProcessingUrl("/login")
                .defaultSuccessUrl("/")
                .permitAll();
        //注销
        http.logout()
                .logoutUrl("/toLogout")
                .logoutSuccessUrl("/").permitAll();
        //开启记住我功能。本质就是加了一个cookie
        http.rememberMe().rememberMeParameter("remember");
    }

    //认证
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //从内存认证
        auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder())
                .withUser("Izumi Sakai").password(new BCryptPasswordEncoder().encode("123456IS")).roles("vip1","vip2")
                .and()
                .withUser("Zhang San").password(new BCryptPasswordEncoder().encode("123456ZS")).roles("vip3");
        //从jdbc数据库认证
        //auth.jdbcAuthentication();
    }
}

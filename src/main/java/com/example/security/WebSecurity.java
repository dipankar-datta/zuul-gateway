package com.example.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

@Configuration
@EnableWebSecurity
public class WebSecurity extends WebSecurityConfigurerAdapter {

    private Environment environment;

    @Autowired
    public WebSecurity(Environment environment) {
        this.environment = environment;
    }


    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.csrf().disable();
        httpSecurity.headers().frameOptions().disable();
        httpSecurity.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        httpSecurity.authorizeRequests()
                .antMatchers(HttpMethod.POST, environment.getProperty("api.registration.path")).permitAll()
                .antMatchers(HttpMethod.POST, environment.getProperty("api.login.path")).permitAll()
                .antMatchers(environment.getProperty("api.h2.console.path")).permitAll()
                .antMatchers(environment.getProperty("api.zuul.actuator.path")).permitAll()
                .antMatchers(environment.getProperty("api.users.actuator.pat")).permitAll()
                .anyRequest().authenticated()
                .and()
                .addFilter(new AuthenticationFilter(authenticationManager(), environment));
    }

}

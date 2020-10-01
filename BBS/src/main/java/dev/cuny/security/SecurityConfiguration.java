package dev.cuny.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.cuny.security.jwt.DefaultTokenManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * @author William Gentry
 */
@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

  private final UserDetailsService clientUserDetailsService;
  private final ObjectMapper mapper;
  private final DefaultTokenManager defaultTokenManager;

  public SecurityConfiguration(UserDetailsService clientUserDetailsService, ObjectMapper mapper, DefaultTokenManager defaultTokenManager) {
    this.clientUserDetailsService = clientUserDetailsService;
    this.mapper = mapper;
    this.defaultTokenManager = defaultTokenManager;
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Override
  @Bean
  public AuthenticationManager authenticationManagerBean() throws Exception {
    return super.authenticationManagerBean();
  }

  @Bean
  public AuthenticationProvider authenticationProvider() {
    return new BugBountyAuthenticationProvider(clientUserDetailsService, passwordEncoder());
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http
      .cors()
        .disable()
      .csrf()
        .disable()
      .formLogin()
        .disable()
      .httpBasic()
        .disable()
      .anonymous()
        .disable()
      .authorizeRequests()
        .mvcMatchers("/login", HttpMethod.POST.toString())
          .permitAll()
        .anyRequest()
          .authenticated()
        .and()
      .addFilterAt(new JwtPresentFilter(defaultTokenManager, clientUserDetailsService), UsernamePasswordAuthenticationFilter.class)
      .addFilterAfter(new LoginFilter(mapper, authenticationProvider(), defaultTokenManager), UsernamePasswordAuthenticationFilter.class);
  }
}

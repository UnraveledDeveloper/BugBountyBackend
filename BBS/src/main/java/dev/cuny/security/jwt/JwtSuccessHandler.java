package dev.cuny.security.jwt;

import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author William Gentry
 */
public class JwtSuccessHandler implements AuthenticationSuccessHandler {

  private final TokenSigner tokenSigner;

  public JwtSuccessHandler(TokenSigner tokenSigner) {
    this.tokenSigner = tokenSigner;
  }

  @Override
  public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
    final String token = tokenSigner.sign(authentication);
    response.addHeader(HttpHeaders.AUTHORIZATION, token);
  }
}

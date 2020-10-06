package dev.cuny.security.jwt;

import dev.cuny.security.BugBountyRole;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.apache.maven.shared.utils.StringUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import javax.crypto.SecretKey;
import java.security.Key;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

/**
 * @author William Gentry
 */
public abstract class AbstractTokenManager implements TokenParser, TokenSigner {

  private final Key signingKey;
  private final SignatureAlgorithm signatureAlgorithm;
  public static final String TOKEN_HEADER_PREFIX = "Bearer ";

  public AbstractTokenManager() {
    final SecretKey secret = Keys.secretKeyFor(SignatureAlgorithm.HS256);
    this.signingKey = Keys.hmacShaKeyFor(secret.getEncoded());
    this.signatureAlgorithm = SignatureAlgorithm.HS256;
  }

  public AbstractTokenManager(Key signingKey, SignatureAlgorithm signatureAlgorithm) {
    this.signingKey = signingKey;
    this.signatureAlgorithm = signatureAlgorithm;
  }

  @Override
  public Authentication parse(String token) {
    if (StringUtils.isBlank(token)) {
      return null;
    }
    Claims claims = Jwts.parser().setSigningKey(signingKey).parseClaimsJws(token).getBody();
    if (!isValid(claims)) {
      return null;
    }
    return new JwtPresentToken(claims.getSubject(), getClientRole(claims));
  }

  @Override
  public String sign(Authentication authentication) {
    Date issuedAt = new Date(System.currentTimeMillis());
    Date expiresAt = Date.from(issuedAt.toInstant().plus(1L, ChronoUnit.DAYS));
    List<String> authorities = authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList());
    final String token = Jwts.builder()
               .signWith(signingKey, signatureAlgorithm)
               .setSubject(authentication.getName())
               .setIssuedAt(issuedAt)
               .setExpiration(expiresAt)
               .claim("roles", String.join(",", authorities))
               .compact();
    return String.format("%s%s", TOKEN_HEADER_PREFIX, token);
  }

  private boolean isValid(Claims claims) {
    return claims.getIssuedAt() != null &&
           claims.getExpiration() != null &&
           claims.getIssuedAt().before(claims.getExpiration());
  }

  private Collection<? extends GrantedAuthority> getClientRole(Claims claims) {
    String roles = (String) claims.get("roles");
    if (StringUtils.isBlank(roles)) {
      throw new RuntimeException();
    }
    return Arrays.stream(roles.split(",")).map(BugBountyRole::valueOf).collect(Collectors.toList());
  }
}

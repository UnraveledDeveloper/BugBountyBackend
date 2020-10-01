package dev.cuny.dtos;

import java.util.Objects;
import java.util.StringJoiner;

/**
 * @author William Gentry
 */
public class LoginFormDto {

  private String email;
  private String password;

  public String getEmail() {
    return email;
  }

  public void setEmail(String email) {
    this.email = email;
  }

  public String getPassword() {
    return password;
  }

  public void setPassword(String password) {
    this.password = password;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    LoginFormDto that = (LoginFormDto) o;
    return Objects.equals(getEmail(), that.getEmail()) &&
            Objects.equals(getPassword(), that.getPassword());
  }

  @Override
  public int hashCode() {
    return Objects.hash(getEmail(), getPassword());
  }

  @Override
  public String toString() {
    return new StringJoiner(", ", LoginFormDto.class.getSimpleName() + "[", "]")
            .add("email='" + email + "'")
            .add("password='" + password + "'")
            .toString();
  }
}

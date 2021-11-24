package com.example.crud.jwt;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;
import java.util.Date;

@Getter
@Setter
@NoArgsConstructor
@Entity(name = "refresh_token")
public class RefreshToken {

  @Id
  @Column(nullable = false, unique = true, length = 60)
  private String userId;

  @Column(nullable = false, unique = true, length = 128)
  private String userName;

  @Column(nullable = false)
  private String token;

  @Column(nullable = false)
  private Date expiryDate;

  public RefreshToken(String token, String userId, String userName, Date expiryDate) {
    this.userId = userId;
    this.userName = userName;
    this.token = token;
    this.expiryDate = expiryDate;
  }
}

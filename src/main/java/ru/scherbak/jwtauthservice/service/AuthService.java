package ru.scherbak.jwtauthservice.service;

import io.jsonwebtoken.Claims;
import lombok.AccessLevel;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import ru.scherbak.jwtauthservice.domain.JwtAuthentication;
import ru.scherbak.jwtauthservice.domain.JwtRequest;
import ru.scherbak.jwtauthservice.domain.JwtResponse;
import ru.scherbak.jwtauthservice.domain.User;
import ru.scherbak.jwtauthservice.exception.AuthException;

@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class AuthService {
    UserService userService;
    JwtService jwtService;

    public JwtResponse login(@NonNull JwtRequest authRequest) {
        final User user = userService.getByLogin(authRequest.getLogin())
                .orElseThrow(() -> new AuthException("Неправильный логин или пароль!"));
        if (user.getPassword().equals(authRequest.getPassword())) {
            String accessToken = jwtService.generateAccessToken(user);
            String refreshToken = jwtService.generateRefreshToken(user);
            return new JwtResponse(accessToken, refreshToken, "Bearer");
        } else {
            throw new AuthException("Неправильный логин или пароль!");
        }
    }

    public JwtResponse getAccessToken(@NonNull String refreshToken) {
        if (jwtService.validateRefreshToken(refreshToken)) {
            Claims claims = jwtService.getRefreshClaims(refreshToken);
            String login = claims.getSubject();
            User user = userService.getByLogin(login)
                    .orElseThrow(() -> new AuthException("Пользователь не найден"));
            String accessToken = jwtService.generateAccessToken(user);
            return new JwtResponse(accessToken, refreshToken, "Bearer");
        }
        return new JwtResponse();
    }

    public JwtResponse refresh(@NonNull String refreshToken) {
        if (jwtService.validateRefreshToken(refreshToken)) {
            Claims claims = jwtService.getRefreshClaims(refreshToken);
            String login = claims.getSubject();
            User user = userService.getByLogin(login)
                    .orElseThrow(() -> new AuthException("Пользователь не найден"));
            String accessToken = jwtService.generateAccessToken(user);
            String newRefreshToken = jwtService.generateRefreshToken(user);
            return new JwtResponse(accessToken, newRefreshToken, "Bearer");
        }
        throw new AuthException("Невалидный JWT токен");
    }

    public JwtAuthentication getAuthInfo() {
        return (JwtAuthentication) SecurityContextHolder.getContext().getAuthentication();
    }

}

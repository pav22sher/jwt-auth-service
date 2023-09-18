package ru.scherbak.jwtauthservice.service;

import lombok.NonNull;
import org.springframework.stereotype.Service;
import ru.scherbak.jwtauthservice.domain.Role;
import ru.scherbak.jwtauthservice.domain.User;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

@Service
public class UserService {
    private final List<User> users;

    public UserService() {
        this.users = List.of(
                new User("user", "user", "Юзер", "Юзеров", Collections.singleton(Role.USER)),
                new User("admin", "admin", "Админ", "Админов", Collections.singleton(Role.ADMIN))
        );
    }

    public Optional<User> getByLogin(@NonNull String login) {
        return users.stream()
                .filter(user -> login.equals(user.getLogin()))
                .findFirst();
    }
}

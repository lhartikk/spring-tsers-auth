package org.tsers.springtsers.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.tsers.springtsers.model.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findOneByLogin(String login);

}

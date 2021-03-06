package com.mapper;

import com.entities.User;
import org.apache.ibatis.annotations.Mapper;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
@Mapper
public interface UserMapper {
    List<User> findAll();
    User findByUserName(String userName);
    void insert(User user);
}

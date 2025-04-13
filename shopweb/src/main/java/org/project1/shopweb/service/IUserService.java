package org.project1.shopweb.service;

import org.project1.shopweb.dto.UpdateUserDTO;
import org.project1.shopweb.model.User;

import org.project1.shopweb.dto.UserDTO;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

public interface IUserService {


    User createUser(UserDTO userDTO) throws  Exception;
    String login(String phonenumber,String password, Long roleId) throws  Exception;

    User getUserDetailFromToken(String token);

    User updateUser(Long userId, UpdateUserDTO userDTO);

    User getUserDetailsFromRefreshToken(String refreshToken) throws Exception;

    Page<User> findAll(String keyword, Pageable pageable) throws Exception;

    void resetPwd(String newPass, Long id);

    void blockOrEnable(Long id,Boolean active);
}



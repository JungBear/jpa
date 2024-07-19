package com.jsp.jpa.service;

import com.jsp.jpa.dto.AuthDto;
import org.springframework.stereotype.Service;

@Service
public interface UserService {

    public void registerUser(AuthDto.SignupDto signupDto);
}

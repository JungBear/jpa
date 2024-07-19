package com.jsp.jpa.dto;

import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * 인증과정에서 필요한 DTO
 */
public class AuthDto {

    @Getter
    @NoArgsConstructor(access = AccessLevel.PROTECTED)
    public static class LoginDto {
        private String email;
        private String password;

        @Builder
        /**
         * 로그인할 때 필요하다
         */
        public LoginDto(String email, String password) {
            this.email = email;
            this.password = password;
        }
    }

    @Getter
    @NoArgsConstructor(access = AccessLevel.PROTECTED)
    /**
     * 회원가입할 때 필요하다
     */
    public static class SignupDto {
        private String email;
        private String password;

        @Builder
        public SignupDto(String email, String password) {
            this.email = email;
            this.password = password;
        }

        public static SignupDto encodePassword(SignupDto signupDto, String encodedPassword) {
            SignupDto newSignupDto = new SignupDto();
            newSignupDto.email = signupDto.getEmail();
            newSignupDto.password = encodedPassword;
            return newSignupDto;
        }
    }

    @Getter
    @NoArgsConstructor(access = AccessLevel.PROTECTED)
    public static class TokenDto {
        private String accessToken;
        private String refreshToken;

        public TokenDto(String accessToken, String refreshToken) {
            this.accessToken = accessToken;
            this.refreshToken = refreshToken;
        }
    }
}
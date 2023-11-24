package com.example.springboot3oauth2authorizationserver.handler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import java.io.IOException;

public class CustomAccessDeniedHandler implements AccessDeniedHandler {

    //handle 메서드는 메서드 아거먼트중 하나가 발생하면 우리가 정의한 특정 동작을 수행
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException, ServletException {
        // 접근이 거부 됐을 때 "/access-denied" 로 리턴 (이 특정 페이지로 리다이렉션)
        response.sendRedirect("/access-denied");
    }
}

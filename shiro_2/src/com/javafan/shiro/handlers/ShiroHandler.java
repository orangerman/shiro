package com.javafan.shiro.handlers;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * @author fanfan
 */


@Controller
@RequestMapping("/shiro")
public class ShiroHandler {


    @RequestMapping("/login")
    public String login(@RequestParam("username") String username, @RequestParam("password") String password) {


        Subject currentUser = SecurityUtils.getSubject();

        if (!currentUser.isAuthenticated()) {
            UsernamePasswordToken token = new UsernamePasswordToken(username, password);
            token.setRememberMe(true);
            try {
                //执行登陆
                currentUser.login(token);

            } catch (AuthenticationException ae) {

                System.out.println("登陆失败: " + ae.getMessage());
            }
        }

        return "redirect:/list.jsp";
    }
}

package com.controller;

import com.entities.User;
import com.mapper.UserMapper;
import com.realms.UserRealm;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.LockedAccountException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.crypto.hash.Md5Hash;
import org.apache.shiro.subject.Subject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.http.HttpServletRequest;

@Controller
public class UserController {
    @Autowired
    private UserMapper userMapper;

    @RequestMapping("/toLogin")
    public String login(){
        return "login";
    }
    @RequestMapping("/login")
    public String toLogin(String username, String password, Model model){
        //获取主体的方法永远都是这个
        Subject subject = SecurityUtils.getSubject();
        //创建一个令牌token，传入表单的账号和密码
        UsernamePasswordToken token = new UsernamePasswordToken(username, password);
        //尝试登陆并捕获错误
        try{
            subject.login(token);
            return "index";
        }catch (UnknownAccountException e){
            model.addAttribute("error","用户名不存在");
            return "forward:toLogin";
        }catch (IncorrectCredentialsException e){
            model.addAttribute("error","密码错误");
            return "forward:toLogin";
        }catch (LockedAccountException e){
            model.addAttribute("error","此账户已被锁定，请联系管理员");
            return "forward:toLogin";
        }
    }

    @RequestMapping("/register")
    public String toRegister(HttpServletRequest request){
        //从HttpServletRequest获取参数，其实可以直接获取
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        //设置盐值
        String salt=String.valueOf(Math.round(Math.random()*10000));
        //设置加密后的密码
        String hexPassword = new Md5Hash(password, salt, 1024).toHex();
        //把新注册的用户insert到数据库
        User user=new User();
        user.setUserName(username);
        user.setPassword(hexPassword);
        user.setSalt(salt);
        userMapper.insert(user);
        return "login";
    }

    @RequestMapping("/toRegister")
    public String register(){
        return "register";
    }

    @RequestMapping("/unauthorized")
    public String unauthorized(){
        return "unauthorized";
    }
}

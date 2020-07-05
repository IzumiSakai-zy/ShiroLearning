package com.test;

import com.Realm.MyRealm;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.subject.Subject;

public class TestMyRealm {
    public static void main(String[] args) {
        DefaultSecurityManager defaultWebSecurityManager =new DefaultSecurityManager();
        defaultWebSecurityManager.setRealm(new MyRealm());
        SecurityUtils.setSecurityManager(defaultWebSecurityManager);
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken usernamePasswordToken =
                new UsernamePasswordToken("IzumiSakai","123456I");
        try {
            subject.login(usernamePasswordToken);
            System.out.println("认证成功");
            System.out.println("认证状态："+subject.isAuthenticated());
        }catch (UnknownAccountException e){
            System.out.println("用户名不存在");
            System.out.println("认证状态："+subject.isAuthenticated());
        }catch (IncorrectCredentialsException e){
            System.out.println("密码错误");
            System.out.println("认证状态："+subject.isAuthenticated());
        }
    }
}

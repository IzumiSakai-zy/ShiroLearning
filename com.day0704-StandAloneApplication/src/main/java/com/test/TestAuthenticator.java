package com.test;


import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.text.IniRealm;
import org.apache.shiro.subject.Subject;

public class TestAuthenticator {
    public static void main(String[] args) {
        //创建安全管理器对象
        DefaultSecurityManager securityManager=new DefaultSecurityManager();

        //设置Realm(做认证时就读取这个Realm里面的数据)
        securityManager.setRealm(new IniRealm("classpath:shiro.ini"));

        //给全局的安全工具类设置使用的安全管理器
        SecurityUtils.setSecurityManager(securityManager);

        //关键对象, Subject主体
        Subject subject = SecurityUtils.getSubject();

        //创建令牌
        UsernamePasswordToken usernamePasswordToken = new UsernamePasswordToken("IzumiSakai","123456");

        //执行登录并比较
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

package com.test;

import com.Realm.MyMd5Realm;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.subject.Subject;

import java.util.Arrays;

public class TestMd5Realm {
    public static void main(String[] args) {
        DefaultSecurityManager defaultWebSecurityManager =new DefaultSecurityManager();

        MyMd5Realm myMd5Realm=new MyMd5Realm();
        //创建非默认的CredentialsMatcher
        HashedCredentialsMatcher hashedCredentialsMatcher = new HashedCredentialsMatcher();
        //设置算法的名字
        hashedCredentialsMatcher.setHashAlgorithmName("md5");
        //设置hash散列的次数为1024
        hashedCredentialsMatcher.setHashIterations(1024);
        //调用set方法设置非默认的CredentialsMatcher
        myMd5Realm.setCredentialsMatcher(hashedCredentialsMatcher);
        //把设置后的Realm放入安全管理器
        defaultWebSecurityManager.setRealm(myMd5Realm);

        SecurityUtils.setSecurityManager(defaultWebSecurityManager);
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken usernamePasswordToken =
                new UsernamePasswordToken("Izumi Sakai","123456IS");
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

        //基于角色的访问控制
        if (subject.isAuthenticated()){
            System.out.println("管理员权限"+subject.hasRole("admin"));
            System.out.println("双权限"+subject.hasAllRoles(Arrays.asList("user","admin")));
        }

        //基于资源的访问控制
        if (subject.isAuthenticated()){
            System.out.println("对user模块的01资源是否拥有所有权限"+subject.isPermitted("user:*:01"));
        }
    }
}

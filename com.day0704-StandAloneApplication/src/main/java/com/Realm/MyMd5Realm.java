package com.Realm;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.crypto.hash.Md5Hash;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;

import java.sql.Array;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class MyMd5Realm extends AuthorizingRealm {
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        //获取首用户名
        String primaryPrincipal = principalCollection.getPrimaryPrincipal().toString();

        //根据身份信息、用户名、获取当前用户的角色信息和权限信息
        SimpleAuthorizationInfo authorizationInfo=new SimpleAuthorizationInfo();

        //根据数据库查询的角色信息进行角色分配
        authorizationInfo.addRoles(Arrays.asList("admin","user"));

        //根据数据库查询的角色信息进行角权限分配
        authorizationInfo.addStringPermissions(Arrays.asList("user:*:*","common:create:01"));

        return authorizationInfo;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        String principal = authenticationToken.getPrincipal().toString();
        if ("Izumi Sakai".equals(principal)){
            return new SimpleAuthenticationInfo(
                    "Izumi Sakai",
                    "95cd23ec32d9b359c71cd487b0fcf8d8",
                    ByteSource.Util.bytes("xyz"),//加入的salt
                    this.getName());
        }else
            return null;
    }
}

package com.Realm;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

public class MyRealm extends AuthorizingRealm {
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        return null;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        //获取用户名信息
        String principal = authenticationToken.getPrincipal().toString();
        //假装从数据库获取到用户信息进行比对
        if ("Izumi Sakai".equals(principal)){
            //这样肯定不会报身份信息错误UnknownAccountException
            //参数一：返回数据库正确的用户名，参数二：返回数据库中正确的密码，参数三：提供当前的Realm名
            return new SimpleAuthenticationInfo("IzumiSakai","123456IS",this.getName());
        }else
            return null;
    }
}

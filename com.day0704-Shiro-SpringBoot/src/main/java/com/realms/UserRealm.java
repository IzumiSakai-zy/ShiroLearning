package com.realms;

import com.entities.User;
import com.mapper.UserMapper;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;
import org.springframework.beans.factory.annotation.Autowired;


public class UserRealm extends AuthorizingRealm {
    //数据库层接口
    @Autowired
    private UserMapper userMapper;

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        //获取首用户名，来源是下面方法的第一个参数
        String principal = principalCollection.getPrimaryPrincipal().toString();
        //创建要返回的授权信息
        SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();
        //根据查询数据库添加权限。此处是设置只有Izumi Sakai有权限
        if ("Izumi Sakai".equals(principal))
            authorizationInfo.addStringPermission("/:add:*");//对"/"URL路径下所有实体具有add权限。也就是有"/"
        return authorizationInfo;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        String principal = authenticationToken.getPrincipal().toString();
        User user = userMapper.findByUserName(principal);
        if (user==null)
            return null;
        //第一个参数很关键，它是上面的授权能够获取到的值
        SimpleAuthenticationInfo simpleAuthenticationInfo = new SimpleAuthenticationInfo(
                user.getUserName(),
                user.getPassword(),
                ByteSource.Util.bytes(user.getSalt()),
                this.getName());
        return simpleAuthenticationInfo;
    }
}

package com.javafan.shiro.realms;

import org.apache.shiro.authc.*;
import org.apache.shiro.realm.AuthenticatingRealm;
import org.apache.shiro.realm.Realm;

/**
 * @author fanfan
 */
public class ShiroRealm extends AuthenticatingRealm {

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
//        System.out.println("doGetAuthenticationInfo" + token);

        //1.把AuthenticationToken转化为UsernamepasswordToken
        UsernamePasswordToken upToken = (UsernamePasswordToken) token;

        //2.从UsernamepasswordToken中获取username
        String username = upToken.getUsername();

        //3.调用数据库的方法 从数据库中取出username对应的用户记录
        System.out.println("c从数据库中获取Username: " + username + "所对应的用户信息");

        //4.若用户不存在 则可以抛出UnknownAccountException
        if ("unknow".equals(username)) {
            throw new UnknownAccountException("用户不存在！");

        }

        //5.根据用户信息的情况 决定是否要抛出其他的异常
        if ("master".equals(username)) {
            throw new LockedAccountException("用户被锁定");
        }


        //6.根据用户的情况 来构建AuthenticationInfo 并返回
        //通常使用的实现类为SimpleAuthenticationInfo

        Object principal = username;
        Object credentials = "123456";
        String realmName = getName();
        SimpleAuthenticationInfo info = new SimpleAuthenticationInfo(principal, credentials, realmName);
        return info;
    }
}

package com.javafan.shiro.realms;

import org.apache.shiro.authc.*;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.realm.AuthenticatingRealm;
import org.apache.shiro.util.ByteSource;

/**
 * @author fanfan
 */
public class SecondRealm extends AuthenticatingRealm {

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        System.out.println("SecondRealm + doGetAuthenticationInfo " );

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

        //1.principal 认证的实体信息 可以是username 也可以是数据表对应的用户的实体类对象
        Object principal = username;

        //question_one:加密密码 ====》MD5
        //替换realm的CredentialsMatcher =====>HashCredentialsMathcer

        //MD5加密后的密码
        // "fc1709d0a95a6be30bc5926fdb7f22f4";
        Object credentials = null;
        if ("admin".equals(username)) {
            credentials = "ce2f6417c7e1d32c1d81a797ee0b499f87c5de06";
        }
        if ("user".equals(username)) {

            credentials = "073d4c3ae812935f23cb3f2a71943f49e082a718";
        }

        String realmName = getName();

        //盐值:唯一确定的string
        ByteSource credentialSalt = ByteSource.Util.bytes(username);
        //new SimpleAuthenticationInfo(principal, credentials, realmName);
        SimpleAuthenticationInfo info = null;
        info = new SimpleAuthenticationInfo(principal, credentials, credentialSalt, realmName);
        return info;
    }

    public static void main(String[] args) {
        String hashAlgorithmName = "SHA1";
        Object credentials = "123456";
        Object salt = ByteSource.Util.bytes("admin");
        int hashItertions = 1024;
        Object result = new SimpleHash(hashAlgorithmName, credentials, salt, hashItertions);
        System.out.println(result);

    }
}

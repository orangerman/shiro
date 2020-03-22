package com.javafan.shiro.realms;

import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.realm.AuthenticatingRealm;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;
import org.springframework.jdbc.support.nativejdbc.JBossNativeJdbcExtractor;

import java.util.HashSet;
import java.util.Set;

/**
 * @author fanfan
 */
public class ShiroRealm extends AuthorizingRealm {

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        System.out.println("First ShiroRealm doGetAuthenticationInfo");

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
        Object credentials = null;//"fc1709d0a95a6be30bc5926fdb7f22f4";
        if ("admin".equals(username)) {
            credentials = "038bdaf98f2037b31f1e75b5b4c9b26e";
        }
        if ("user".equals(username)) {

            credentials = "098d2c478e9c11555ce2823231e02ec1";
        }

        String realmName = getName();

        //盐值:唯一确定的string
        ByteSource credentialSalt = ByteSource.Util.bytes(username);
        //new SimpleAuthenticationInfo(principal, credentials, realmName);
        SimpleAuthenticationInfo info = null;
        info = new SimpleAuthenticationInfo(principal, credentials, credentialSalt, realmName);
        return info;
    }

    /**
     * 授权方法
     * @param principalCollection
     * @return
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
//        System.out.println("ShiroRealm doGetAuthorizationInfo......");
        //1.从PrincipalCollection 获取登陆用户的信息
        Object principals = principalCollection.getPrimaryPrincipal();
        System.out.println(principals);

        //2.利用登陆用户的信息来得到当前用户的角色或者权限信息（可能需要查询DB）
        Set<String> roles = new HashSet<String>();
        roles.add("user");
        if ("admin".equals(principals)) {
            roles.add("admin");
        }

        //3.创建SimpleAuthorizationInfo，来设置其roles属性
        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo(roles);
        //4.返回创建SimpleAuthorizationInfo
        return info;
    }

//    public static void main(String[] args) {
//        String hashAlgorithmName = "MD5";
//        Object credentials = "123456";
//        Object salt = ByteSource.Util.bytes("user");
//        int hashItertions = 1024;
//        Object result = new SimpleHash(hashAlgorithmName, credentials, salt, hashItertions);
//        System.out.println(result);
//
//    }
}

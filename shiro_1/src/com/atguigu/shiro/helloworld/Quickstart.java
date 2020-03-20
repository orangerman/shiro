package com.atguigu.shiro.helloworld;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Factory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Simple Quickstart application showing how to use Shiro's API.
 *
 * @since 0.9 RC2
 */
public class Quickstart {

    private static final transient Logger log = LoggerFactory.getLogger(Quickstart.class);


    public static void main(String[] args) {

        // The easiest way to create a Shiro SecurityManager with configured
        // realms, users, roles and permissions is to use the simple INI config.
        // We'll do that by using a factory that can ingest a .ini file and
        // return a SecurityManager instance:

        // Use the shiro.ini file at the root of the classpath
        // (file: and url: prefixes load from files and urls respectively):
        Factory<SecurityManager> factory = new IniSecurityManagerFactory("classpath:shiro.ini");
        SecurityManager securityManager = factory.getInstance();


        SecurityUtils.setSecurityManager(securityManager);


        //获取当前的subject 调用SecurityUtils.getSubject()
        Subject currentUser = SecurityUtils.getSubject();


        //测试使用Session
        //1.获取Session  getSession（）
        Session session = currentUser.getSession();
        session.setAttribute("someKey", "aValue");
        String value = (String) session.getAttribute("someKey");
        //测试当前的用户是否已经被认证 即是否已经登陆
        if (value.equals("aValue")) {
            log.info("---> Retrieved the correct value! [" + value + "]");
        }


        if (!currentUser.isAuthenticated()) {
            //把用户名和password封装成UsernamePasswordToken对象
            UsernamePasswordToken token = new UsernamePasswordToken("lonestarr", "vespa");
            //remember me
            token.setRememberMe(true);
            try {

                //执行登陆
                currentUser.login(token);
            }
            //若没有指定的账号 则shiro将会抛出UnknownAccountException
            catch (UnknownAccountException uae) {
                log.info("----> There is no user with username of " + token.getPrincipal());
                return; 
            } 

            //若账号存在  但是密码不对 抛出IncorrectCredentialsException
            catch (IncorrectCredentialsException ice) {
                log.info("----> Password for account " + token.getPrincipal() + " was incorrect!");
                return; 
            }
            //用户被锁定的异常 LockedAccountException
            catch (LockedAccountException lae) {
                log.info("The account for username " + token.getPrincipal() + " is locked.  " +
                        "Please contact your administrator to unlock it.");
            }

            //所有认证时异常的父类
            catch (AuthenticationException ae) {

            }
        }


        log.info("----> User [" + currentUser.getPrincipal() + "] logged in successfully.");

        //test是否有该角色
        //调用了subject的hasRole（String s）
        if (currentUser.hasRole("schwartz")) {
            log.info("----> May the Schwartz be with you!");
        } else {
            log.info("----> Hello, mere mortal.");
            return; 
        }

        //test用户是否具备某一个行为
        //调用subject的isPermitted（String str）
        if (currentUser.isPermitted("lightsaber:weild")) {
            log.info("----> You may use a lightsaber ring.  Use it wisely.");
        } else {
            log.info("Sorry, lightsaber rings are for schwartz masters only.");
        }


        //test是否用户是否具有某一个特定的行为
        if (currentUser.isPermitted("user:delete:zhangsan")) {
            log.info("----> You are permitted to 'drive' the winnebago with license plate (id) 'eagle5'.  " +
                    "Here are the keys - have fun!");
        } else {
            log.info("Sorry, you aren't allowed to drive the 'eagle5' winnebago!");
        }

        //all done - log out!
        System.out.println("---->" + currentUser.isAuthenticated());

        //执行登出
        //调用subject的logout方法
        currentUser.logout();
        
        System.out.println("---->" + currentUser.isAuthenticated());

        System.exit(0);
    }
}

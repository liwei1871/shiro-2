package com.atguigu.shiro;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;

public class MyRealm extends AuthorizingRealm {

	/**
	 * 当访问受保护的资源时, shiro 会调用 doGetAuthorizationInfo 方法.
	 * 可以从 PrincipalCollection 类型的参数中来获取当前登陆用户的信息.
	 */
	//进行授权的方法
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(
			PrincipalCollection principals) {
		//1. 调用 PrincipalCollection 的 getPrimaryPrincipal() 方法来获取
		//登陆信息.
		Object principal = principals.getPrimaryPrincipal();
		
		//2. 若登陆信息中没包含了权限信息, 则利用 1 的 principal 来获取权限信息
		System.out.println("登陆用户为:" + principal);
		
		//3. 把权限信息封装为一个 SimpleAuthorizationInfo 对象. 并返回
		SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
		info.addRole("user");
		if("admin".equals(principal)){
			info.addRole("admin");
		}
		if("user".equals(principal)){
			info.addRole("tester");
		}
		
		return info;
	}

	/**
	 * 认证的流程:
	 * 1. 在 Handler 中调用 Subject 的 login(UsernamePasswordToken) 方法 
	 * 2. Shiro 会回调 AuthenticatingRealm 实现类的 doGetAuthenticationInfo 方法.
	 * 且 doGetAuthenticationInfo 方法的参数 AuthenticationToken 的对象即为 调用 Subject 的 login(UsernamePasswordToken)
	 * 方法时传入的参数
	 * 
	 * 关于密码加密:
	 * 1. 为当前的 Realm 的 credentialsMatcher 属性, 重新赋值
	 * 赋值为: 新的 HashedCredentialsMatcher 对象, 且加密算法为 MD5
	 * 2. doGetAuthenticationInfo 方法的返回值为 SimpleAuthenticationInfo, 但需要使用如下的构造器:
	 * SimpleAuthenticationInfo(principal, hashedCredentials, credentialsSalt, realmName)
	 * 3. 如何来计算加密后的密码 ? 
	 * Object result = new SimpleHash(hashAlgorithmName, credentials, salt, hashIterations);
	 */
	//进行认证的方法. 
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(
			AuthenticationToken token) throws AuthenticationException {
		//1. 把 AuthenticationToken 强转为 UsernamePasswordToken
		UsernamePasswordToken upToken = (UsernamePasswordToken) token;
		
		//2. 从 UsernamePasswordToken 中获取 username. 但不需要获取 password
		String username = upToken.getUsername();
		
		//3. 利用 username 调用 dao 方法从数据库中获取对应的用户信息.
		System.out.println("利用 username:" + username + "从数据库中获取用户信息");
		if("AAA".equals(username)){
			throw new UnknownAccountException("----------------------------------------------->");
		}
		
		//4. 把用户信息封装为 SimpleAuthenticationInfo 对象返回
		//以下信息来源于数据表
		//实际登录用户信息. 可以为 username. 也可以是一个实体类的对象。 
		String principal = username;
		//凭证信息. 即密码
		String hashedCredentials = null;
		if("user".equals(username)){
			hashedCredentials = "098d2c478e9c11555ce2823231e02ec1";
		}else if("admin".equals(username)){
			hashedCredentials = "038bdaf98f2037b31f1e75b5b4c9b26e";
		}
		//realm 的 name, 只需要调用 AuthorizingRealm 中已经定义好的 getName() 方法即可.
		String realmName = getName();
		//SimpleAuthenticationInfo info = new SimpleAuthenticationInfo(principal, credentials, realmName);
		
		//若需要使用密码进行盐值加密, 则需要在参加 SimpleAuthenticationInfo 对象时
		//使用 SimpleAuthenticationInfo(principal, hashedCredentials, credentialsSalt, realmName)
		//构造器. 
		//盐值: 通过调用 ByteSource.Util.bytes() 方法来生成盐值
		ByteSource credentialsSalt = ByteSource.Util.bytes(username);
		SimpleAuthenticationInfo info = 
				new SimpleAuthenticationInfo(principal, hashedCredentials, credentialsSalt, realmName);
		
		return info;
	}
	
	public static void main(String[] args) {
		String hashAlgorithmName = "MD5";
		String credentials = "123456";
		ByteSource salt = ByteSource.Util.bytes("admin");
		int hashIterations = 1024;
		Object result = new SimpleHash(hashAlgorithmName, credentials, salt, hashIterations);
		
		System.out.println(result);
	}
}

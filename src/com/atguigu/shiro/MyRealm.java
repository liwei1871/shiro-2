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
	 * �������ܱ�������Դʱ, shiro ����� doGetAuthorizationInfo ����.
	 * ���Դ� PrincipalCollection ���͵Ĳ���������ȡ��ǰ��½�û�����Ϣ.
	 */
	//������Ȩ�ķ���
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(
			PrincipalCollection principals) {
		//1. ���� PrincipalCollection �� getPrimaryPrincipal() ��������ȡ
		//��½��Ϣ.
		Object principal = principals.getPrimaryPrincipal();
		
		//2. ����½��Ϣ��û������Ȩ����Ϣ, ������ 1 �� principal ����ȡȨ����Ϣ
		System.out.println("��½�û�Ϊ:" + principal);
		
		//3. ��Ȩ����Ϣ��װΪһ�� SimpleAuthorizationInfo ����. ������
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
	 * ��֤������:
	 * 1. �� Handler �е��� Subject �� login(UsernamePasswordToken) ���� 
	 * 2. Shiro ��ص� AuthenticatingRealm ʵ����� doGetAuthenticationInfo ����.
	 * �� doGetAuthenticationInfo �����Ĳ��� AuthenticationToken �Ķ���Ϊ ���� Subject �� login(UsernamePasswordToken)
	 * ����ʱ����Ĳ���
	 * 
	 * �����������:
	 * 1. Ϊ��ǰ�� Realm �� credentialsMatcher ����, ���¸�ֵ
	 * ��ֵΪ: �µ� HashedCredentialsMatcher ����, �Ҽ����㷨Ϊ MD5
	 * 2. doGetAuthenticationInfo �����ķ���ֵΪ SimpleAuthenticationInfo, ����Ҫʹ�����µĹ�����:
	 * SimpleAuthenticationInfo(principal, hashedCredentials, credentialsSalt, realmName)
	 * 3. �����������ܺ������ ? 
	 * Object result = new SimpleHash(hashAlgorithmName, credentials, salt, hashIterations);
	 */
	//������֤�ķ���. 
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(
			AuthenticationToken token) throws AuthenticationException {
		//1. �� AuthenticationToken ǿתΪ UsernamePasswordToken
		UsernamePasswordToken upToken = (UsernamePasswordToken) token;
		
		//2. �� UsernamePasswordToken �л�ȡ username. ������Ҫ��ȡ password
		String username = upToken.getUsername();
		
		//3. ���� username ���� dao ���������ݿ��л�ȡ��Ӧ���û���Ϣ.
		System.out.println("���� username:" + username + "�����ݿ��л�ȡ�û���Ϣ");
		if("AAA".equals(username)){
			throw new UnknownAccountException("----------------------------------------------->");
		}
		
		//4. ���û���Ϣ��װΪ SimpleAuthenticationInfo ���󷵻�
		//������Ϣ��Դ�����ݱ�
		//ʵ�ʵ�¼�û���Ϣ. ����Ϊ username. Ҳ������һ��ʵ����Ķ��� 
		String principal = username;
		//ƾ֤��Ϣ. ������
		String hashedCredentials = null;
		if("user".equals(username)){
			hashedCredentials = "098d2c478e9c11555ce2823231e02ec1";
		}else if("admin".equals(username)){
			hashedCredentials = "038bdaf98f2037b31f1e75b5b4c9b26e";
		}
		//realm �� name, ֻ��Ҫ���� AuthorizingRealm ���Ѿ�����õ� getName() ��������.
		String realmName = getName();
		//SimpleAuthenticationInfo info = new SimpleAuthenticationInfo(principal, credentials, realmName);
		
		//����Ҫʹ�����������ֵ����, ����Ҫ�ڲμ� SimpleAuthenticationInfo ����ʱ
		//ʹ�� SimpleAuthenticationInfo(principal, hashedCredentials, credentialsSalt, realmName)
		//������. 
		//��ֵ: ͨ������ ByteSource.Util.bytes() ������������ֵ
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

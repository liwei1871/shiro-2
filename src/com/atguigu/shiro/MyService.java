package com.atguigu.shiro;

import org.apache.shiro.authz.annotation.RequiresRoles;

public class MyService {
	
	/**
	 * ʹ�� shiro ��ע������������ϸ���ȵ�Ȩ�޿���
	 */
	@RequiresRoles("tester")
	public void test(){
		System.out.println("test....");
	}
	
}

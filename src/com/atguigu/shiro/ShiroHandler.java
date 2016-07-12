package com.atguigu.shiro;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class ShiroHandler {
	
	@Autowired
	private MyService myService;
	
	@RequestMapping("/test")
	public String test(){
		myService.test();
		return "success";
	}
	
	@RequestMapping("/shiro-login")
	public String login(@RequestParam("username") String username, 
			@RequestParam("password") String password){
		// ��ȡ��ǰ User: ������ SecurityUtils.getSubject() ����. 
		Subject currentUser = SecurityUtils.getSubject();

		// ����û��Ƿ��Ѿ�����֤. ���û��Ƿ��¼. ���� Subject �� isAuthenticated()
		if (!currentUser.isAuthenticated()) {
			// ���û����������װΪһ�� UsernamePasswordToken ����. 
		    UsernamePasswordToken token = new UsernamePasswordToken(username, password);
		    token.setRememberMe(true);
		    try {
		    	// ִ�е�¼. ���� Subject �� login(UsernamePasswordToken) ����.
		        currentUser.login(token);
		    } 
		    // ��֤ʱ���쳣. ���е���֤ʱ���쳣�ĸ���. 
		    catch (AuthenticationException ae) {
//		    	ae.printStackTrace();
		    	System.out.println("��¼ʧ��:" + ae.getMessage());
		    	return "redirect:/login.jsp";
		    }
		}
		
		return "success";
	}
	
}

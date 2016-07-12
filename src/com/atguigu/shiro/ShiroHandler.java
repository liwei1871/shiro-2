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
		// 获取当前 User: 调用了 SecurityUtils.getSubject() 方法. 
		Subject currentUser = SecurityUtils.getSubject();

		// 检测用户是否已经被认证. 即用户是否登录. 调用 Subject 的 isAuthenticated()
		if (!currentUser.isAuthenticated()) {
			// 把用户名和密码封装为一个 UsernamePasswordToken 对象. 
		    UsernamePasswordToken token = new UsernamePasswordToken(username, password);
		    token.setRememberMe(true);
		    try {
		    	// 执行登录. 调用 Subject 的 login(UsernamePasswordToken) 方法.
		        currentUser.login(token);
		    } 
		    // 认证时的异常. 所有的认证时的异常的父类. 
		    catch (AuthenticationException ae) {
//		    	ae.printStackTrace();
		    	System.out.println("登录失败:" + ae.getMessage());
		    	return "redirect:/login.jsp";
		    }
		}
		
		return "success";
	}
	
}

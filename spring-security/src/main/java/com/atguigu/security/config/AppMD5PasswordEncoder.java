package com.atguigu.security.config;

import org.springframework.security.crypto.password.PasswordEncoder;

import com.atguigu.security.service.MD5Util;
//自定义密码处理器
public class AppMD5PasswordEncoder implements PasswordEncoder {

	@Override
	public String encode(CharSequence rawPassword) {
		//可以使用自己的加密方式对传入的密码进行加密处理
		
		return MD5Util.digest(rawPassword.toString());
	}

	@Override
	public boolean matches(CharSequence rawPassword, String encoderPassword) {
		String loginPws = encode(rawPassword);
		
		return loginPws.equals(encoderPassword);
	}

}

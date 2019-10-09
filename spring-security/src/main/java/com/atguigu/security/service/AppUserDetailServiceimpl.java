package com.atguigu.security.service;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class AppUserDetailServiceimpl implements UserDetailsService {

	@Autowired
	JdbcTemplate jdbcTemplate;
	
	//主体封装的方法
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		// username:用户登录提交的账号
		//1.从数据库中根据账号查询用户信息
		String sql = "SELECT username , loginacct , userpswd , email , id FROM t_admin WHERE loginacct = ?";
		Map<String, Object> map = jdbcTemplate.queryForMap(sql, username);
		List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
		//2.如果用户信息查询成功，从数据库中查询该用户的权限信息
		if(map.get("id") != null) {
			//用户权限集合应该包含角色列表+权限列表：先查角色列表，再根据角色列表查询权限
			sql="SELECT roleid , `name` FROM t_admin_role JOIN t_role ON roleid = t_role.`id` WHERE adminid = ? ";
			//2.1查询角色列表，然后将角色添加到权限集合中
			List<Map<String,Object>> list = jdbcTemplate.queryForList(sql, map.get("id"));
			for (Map<String, Object> m : list) {
				authorities.add(new SimpleGrantedAuthority("ROLE_"+m.get("name").toString()));
			}
			//2.2查询权限列表，然后将权限添加到权限集合中
			sql = "SELECT permissionid , NAME  FROM t_role_permission JOIN t_permission ON permissionid = t_permission.`id` WHERE roleid = ? AND name is not null";
			for (Map<String, Object> m : list) {
				List<Map<String, Object>> permissions = jdbcTemplate.queryForList(sql, m.get("roleid"));
				for (Map<String, Object> permission : permissions) {
					//将正在遍历的权限设置到权限集合中
					authorities.add(new SimpleGrantedAuthority(permission.get("name").toString()));
					
				}
			}
			System.out.println(authorities);
		}
		
		
		//3.封装主体对象返回[登录的中账号，从数据库中查询的密码,权限集合（如果表示角色需要在前面拼接ROLE_前缀）]
		return new User(username, map.get("userpswd").toString(), authorities);
	}

}

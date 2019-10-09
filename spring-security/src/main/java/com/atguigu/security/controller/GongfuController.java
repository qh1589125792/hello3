package com.atguigu.security.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@Controller
public class GongfuController {
	
	@PreAuthorize("hasAnyRole('BOSS')")
	@GetMapping("/level1/1")
	public String leve11Page(){
		return "level1/1";
	}
	@PreAuthorize("hasAnyRole('MANAGER' , 'GL - 组长')")
	@GetMapping("/level1/2")
	public String leve12Page(){
		return "level1/2";
	}
	@PreAuthorize("hasAnyAuthority('user:add','user:delete')")
	@GetMapping("/level1/3")
	public String leve13Page(){
		return "level1/3";
	}
	
	@GetMapping("/level2/{path}")
	public String leve2Page(@PathVariable("path")String path){
		return "level2/"+path;
	}
	
	@GetMapping("/level3/{path}")
	public String leve3Page(@PathVariable("path")String path){
		return "level3/"+path;
	}

}

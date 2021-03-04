package com.springsecurity.config;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

public class MyPasswordEncoder implements PasswordEncoder {
    @Override
    public String encode(CharSequence charSequence) {
        return null;
    }

    @Override
    public boolean matches(CharSequence charSequence, String s) {
        return false;
    }

    public static void main(String[] args) {
        // 创建密码解析器
        BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();

        // 对密码进行加密
        String atguigu = bCryptPasswordEncoder.encode("atguigu");

        // 打印加密之后的数据 System.out.println("加密之后数据:\t"+atguigu);
        //判断原字符加密后和加密之前是否匹配
        boolean result = bCryptPasswordEncoder.matches("atguigu", atguigu); // 打印比较结果
        System.out.println("比较结果:\t" + result);
    }
}

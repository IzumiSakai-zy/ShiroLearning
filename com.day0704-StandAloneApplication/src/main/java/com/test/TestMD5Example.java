package com.test;

import org.apache.shiro.crypto.hash.Md5Hash;

public class TestMD5Example {
    public static void main(String[] args) {
        //使用md5
        Md5Hash md5 = new Md5Hash("Izumi Sakai");
        System.out.println("md5:"+md5.toHex());

        //使用md5+salt
        Md5Hash md5Salt = new Md5Hash("Izumi Sakai","KT*}d`");
        System.out.println("md5+salt:"+md5Salt.toHex());

        //使用md5+salt+hash散列
        Md5Hash md5SaltHash = new Md5Hash("123456IS","xyz",1024);
        System.out.println("md5+salt+hash散列:"+md5SaltHash.toHex());
    }
}

package com.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

@RestController
public class MainController {
    @RequestMapping(value = {"/","index.html"},method = RequestMethod.GET)
    public ModelAndView index(){
        ModelAndView view = new ModelAndView();
        view.setViewName("index");
        return view;
    }

    @RequestMapping(value = "/toLogin",method = RequestMethod.GET)
    public ModelAndView toLogin(){
        ModelAndView view = new ModelAndView();
        view.setViewName("login");
        return view;
    }

    @RequestMapping(value = "/toLogout",method = RequestMethod.GET)
    public ModelAndView toLogout(){
        ModelAndView view = new ModelAndView();
        view.setViewName("logout");
        return view;
    }
}

package com.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

@RestController
public class RouterController {
    @RequestMapping(value = "/level1/level1-1",method = RequestMethod.GET)
    public ModelAndView level1_level1_1(){
        ModelAndView view = new ModelAndView();
        view.setViewName("level1/level1-1");
        return view;
    }
    @RequestMapping(value = "/level1/level1-2",method = RequestMethod.GET)
    public ModelAndView level1_level1_2(){
        ModelAndView view = new ModelAndView();
        view.setViewName("level1/level1-2");
        return view;
    }
    @RequestMapping(value = "/level1/level1-3",method = RequestMethod.GET)
    public ModelAndView level1_level1_3(){
        ModelAndView view = new ModelAndView();
        view.setViewName("level1/level1-3");
        return view;
    }
    @RequestMapping(value = "/level2/level2-1",method = RequestMethod.GET)
    public ModelAndView level2_level1_1(){
        ModelAndView view = new ModelAndView();
        view.setViewName("level2/level2-1");
        return view;
    }
    @RequestMapping(value = "/level2/level2-2",method = RequestMethod.GET)
    public ModelAndView level2_level2_2(){
        ModelAndView view = new ModelAndView();
        view.setViewName("level2/level2-2");
        return view;
    }
    @RequestMapping(value = "/level2/level2-3",method = RequestMethod.GET)
    public ModelAndView level2_level2_3(){
        ModelAndView view = new ModelAndView();
        view.setViewName("level2/level2-3");
        return view;
    }
    @RequestMapping(value = "/level3/level3-1",method = RequestMethod.GET)
    public ModelAndView level3_level3_1(){
        ModelAndView view = new ModelAndView();
        view.setViewName("level3/level3-1");
        return view;
    }
    @RequestMapping(value = "/level3/level3-2",method = RequestMethod.GET)
    public ModelAndView level3_level3_2(){
        ModelAndView view = new ModelAndView();
        view.setViewName("level3/level3-2");
        return view;
    }
    @RequestMapping(value = "/level3/level3-3",method = RequestMethod.GET)
    public ModelAndView level3_level3_3(){
        ModelAndView view = new ModelAndView();
        view.setViewName("level3/level3-3");
        return view;
    }
}

package com.example.digitalsignature;

import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.ModelAndView;

@RestController
public class Controller {

    ServiceImpl service;

    public Controller(ServiceImpl service) {
        this.service = service;
    }

    @GetMapping(value = "/")
    public ModelAndView home(){
        ModelAndView modelAndView = new ModelAndView();
        modelAndView.setViewName("Home");
        return modelAndView;
    }

    @PostMapping(value = "/send")
    public ModelAndView send(Model model, @RequestParam("files")MultipartFile[] files, @RequestParam String email){
        ModelAndView modelAndView = new ModelAndView();
        service.sendDokumentMail(files,email);
        modelAndView.setViewName("Send");
        return modelAndView;
    }
}

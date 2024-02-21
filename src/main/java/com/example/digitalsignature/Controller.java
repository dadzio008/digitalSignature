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

    @PostMapping(value = "/podpisz")
    public ModelAndView podpisz(@RequestParam("files")MultipartFile file, @RequestParam("email")String email){
        ModelAndView modelAndView = new ModelAndView();
        service.sendDokument(file,email);
        modelAndView.setViewName("Podpisz");
        modelAndView.addObject("email",email);
        return modelAndView;
    }

    @PostMapping(value = "/weryfikuj")
    public ModelAndView weryfikuj(@RequestParam("files")MultipartFile file){
        ModelAndView modelAndView = new ModelAndView();
        service.verifyDokument(file.getOriginalFilename());
        modelAndView.setViewName("Weryfikacja");
        return modelAndView;
    }
}

package com.arfaoui.journal.controllers;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("reviewers")
public class reviewerController {

    @GetMapping("/all")
    public void findAll(){

    };
}

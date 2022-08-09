package tf.uiuc.spoink.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.Optional;

@Controller
public class HomeController {
    @RequestMapping({"/"})
    public String getTemplate(@RequestParam("x") Optional<String> template, Model model) {
        return template.orElse("home.pebble");
    }
}
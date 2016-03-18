package org.tsers.springtsers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.tsers.springtsers.stereotypes.CurrentUser;

import javax.servlet.http.HttpServletRequest;
import java.util.Set;

@Controller
public class IndexController {

    @Autowired
    SecurityUtils securityUtils;

    @RequestMapping(value = "/", method = RequestMethod.GET)
    public String index(HttpServletRequest request, Model model) {
        try {
            User u = securityUtils.getCurrentUser();
        } catch (IllegalStateException e) {
            return "index";
        }
        return "forward:/landing";
    }

}

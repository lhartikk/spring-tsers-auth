package org.tsers.springtsers;


import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.tsers.springtsers.stereotypes.CurrentUser;

@Controller
public class LandingController {

	@RequestMapping("/landing")
	public String landing(@CurrentUser User user, Model model) {
		model.addAttribute("username", 	user.getUsername());
		return "landing";
	}

}

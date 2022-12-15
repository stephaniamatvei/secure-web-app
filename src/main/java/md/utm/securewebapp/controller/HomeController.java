package md.utm.securewebapp.controller;

import md.utm.securewebapp.service.CaesarService;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class HomeController {

    @GetMapping("/home")
    public String home(Principal principal) {
        String plaintext = "now you have the permission to play with caesar cipher";
        String ciphertext = "xyg iye rkfo dro zobwsccsyx dy zvki gsdr mkockb mszrob";

        CaesarService caesarService = new CaesarService();

        StringBuilder encryptedMessage = caesarService.encrypt(plaintext, 3);
        StringBuilder decryptedMessage = caesarService.decrypt(ciphertext, 36);

        return "Hello, " + principal.getName() + " ! \n"
                + encryptedMessage + "\n" + decryptedMessage;
    }

    @PreAuthorize("hasAuthority('SCOPE_read')")
    @GetMapping("/secure")
    public String secure() {
        return "This is secured!";
    }
}

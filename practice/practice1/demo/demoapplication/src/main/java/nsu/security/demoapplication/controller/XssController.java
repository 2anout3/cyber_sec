package nsu.security.demoapplication.controller;

import org.owasp.encoder.Encode;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class XssController {
    @GetMapping(value = "/search", produces = MediaType.TEXT_HTML_VALUE)
    public String getNotXss(@RequestParam String query) {
        return "<html><body>" +
               "<h1>Result</h1>" +
               "<p>" + Encode.forHtml(query) + "</p>" +
               "</body></html>";
    }

    @GetMapping(value = "/searchX", produces = MediaType.TEXT_HTML_VALUE)
    public String getXss(@RequestParam String query) {
        return "<html><body>" +
               "<h1>Result</h1>" +
               "<p>" + query + "</p>" +
               "</body></html>";
    }
}

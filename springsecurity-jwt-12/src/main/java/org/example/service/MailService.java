package org.example.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.UrlResource;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;
import javax.servlet.http.HttpServletRequest;
import java.net.MalformedURLException;

@Service
public class MailService {
    private final Logger log = LoggerFactory.getLogger(MailService.class);
    private final JavaMailSender mailSender;
    private final HttpServletRequest request;

    public MailService(JavaMailSender mailSender, HttpServletRequest request) {
        this.mailSender = mailSender;
        this.request = request;
    }

    public String sendMail(String mail, String key){
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = null;
        try {
            helper = new MimeMessageHelper(message, true);
            helper.setTo(mail);
            helper.setSubject("Active Account");
            String url = "http://" + request.getServerName() + ":" + request.getServerPort() +
                    "/active?activationKey=" + key;
            String htmlContent =
                    "<html>" +
                        "<body>" +
                            "<p>Vui lòng click vào đường link bên dưới để kích hoạt tài khoản</p>" +
                            "<br>" +
                            "<p>Lưu ý đường link chỉ có hiệu lực trong vòng 10 phút kể từ lúc đăng ký</p>" +
                            "<p>" +
                                "<a href=\"" + url + "\">" + "Click để active" + "</a>" +
                            "</p>" +
                        "</body>" +
                    "</html>";
            helper.setText(htmlContent, true);
            mailSender.send(message);
            log.info("Email sending success: " + mail);
            return "Please check your mailbox to active your account.";
        } catch (MessagingException e) {
            log.error("Email sending fail!");
            throw new RuntimeException(e);
        }

    }
}

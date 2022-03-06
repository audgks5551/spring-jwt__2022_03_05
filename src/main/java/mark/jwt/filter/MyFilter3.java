package mark.jwt.filter;

import lombok.extern.slf4j.Slf4j;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

@Slf4j
public class MyFilter3 implements Filter {
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        log.info("필터3");

        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        if (req.getMethod().equals("POST")) {
            String headerAuth = req.getHeader("Authorization");
            chain.doFilter(request, response);
            log.info("headerAuth = {}", headerAuth);
            if (headerAuth.equals("cos")) {

            } else {
                PrintWriter writer = res.getWriter();
                writer.println("인증 안됨");
            }
        }
    }
}

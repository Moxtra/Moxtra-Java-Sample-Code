package com.moxtra.webapp.api;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


/**
 * This servlet is to handle AuthnRequest and user login.
 * Do a page-redirect Assertion back to SP.
 */
public class ErrorServlet extends HttpServlet {
	  
	/**
	 * The service method handles return error 
	 */
	  
    @Override
    protected void service(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {	  
	  
		String title = "API Request Error";
		
	    Throwable throwable = (Throwable) request.getAttribute("javax.servlet.error.exception");
	    Throwable cause = throwable.getCause();
	    String message = throwable.getMessage();
	    
		// prepare message to print
		PrintWriter out = response.getWriter();
		out.println("<HTML>");
		out.println("<HEAD>\n");
		out.println("<TITLE>" + title + "</TITLE>\n");
		out.println("</HEAD>\n");
		out.println("<BODY>");
		
		out.println("<H3>" + title + "</H3><BR/>");
		out.println("Message: " + message);
		if (cause != null) {
			out.println("<BR/>");
			out.println("Cause: " + cause.getMessage()); 
		}
		out.println("</BODY></HTML>");
		out.close();		
		
	}
}
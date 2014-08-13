package org.meri.matasano.utils.webtools;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.ServletHandler;
import org.meri.matasano.utils.webtools.servlets.Set4Ex31Servlet;
import org.meri.matasano.utils.webtools.servlets.Set4Ex32Servlet;

public class JettyWebServer {

  private Server server;

  public void start() {
    server = new Server(8080);
    ServletHandler handler = new ServletHandler();
    server.setHandler(handler);
    handler.addServletWithMapping(Set4Ex31Servlet.class, "/Set4Ex31/*");
    handler.addServletWithMapping(Set4Ex32Servlet.class, "/Set4Ex32/*");
    try {
      server.start();
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public void stop() {
    try {
      server.stop();
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

}

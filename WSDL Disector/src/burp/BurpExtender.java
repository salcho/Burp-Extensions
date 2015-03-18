package burp;

import java.io.PrintWriter;
import org.w3c.dom.*;
import javax.xml.parsers.*;
import java.io.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.xml.sax.SAXException;

/**
 *
 * @author salcho
 */
public class BurpExtender implements IBurpExtender,IHttpListener,IExtensionStateListener {

    
    private PrintWriter stdout;
    private PrintWriter stderr;
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        this.callbacks = callbacks;
        this.helpers = this.callbacks.getHelpers();
        
        // set our extension name
        callbacks.setExtensionName("WSDL Mini-Dissector");
        
        // obtain our output and error streams
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);
        
        // Mark XML HTTP services
        callbacks.registerHttpListener(this);
    }
    
    @Override
    public void processHttpMessage(int toolFlag, boolean isRequest, IHttpRequestResponse messageInfo){
        IRequestInfo reqInfo = this.helpers.analyzeRequest(messageInfo.getHttpService(), messageInfo.getRequest());
        String reqURL = reqInfo.getUrl().toString().toLowerCase();
        if(isRequest){
            // Check extension    
            if((reqURL.contains("?wsdl") || reqURL.contains(".wsdl"))){
                // Highlight
                messageInfo.setHighlight("red");
                messageInfo.setComment("wsdl");
                stdout.println("Tool was -> "+this.callbacks.getToolName(toolFlag) + "; "+(isRequest ? "Outbound" : "Inbound")+
                "\tTo -> "+messageInfo.getHttpService().getProtocol()+"://"+messageInfo.getHttpService().getHost()+":"+messageInfo.getHttpService().getPort()
                +"\t URL is -> "+reqURL);
            }
        }else{
            // If this was marked
            if(messageInfo.getComment().equals("wsdl")){
                IResponseInfo rspInfo = this.helpers.analyzeResponse(messageInfo.getResponse());
                // If we actually got the XML
                if(rspInfo.getStatusCode() == 200 && rspInfo.getStatedMimeType().equalsIgnoreCase("XML")){
                    // Buid the extension from here!
                    simpleParse(messageInfo, rspInfo);
                  }
                }
            }
        }
    
    @Override
    public void extensionUnloaded(){
        stdout.println("Extension unloaded");
    }
    
    public void simpleParse(IHttpRequestResponse messageInfo, IResponseInfo rspInfo){
        try {
            //String wsdl = this.helpers.bytesToString(messageInfo.getResponse()).substring(rspInfo.getBodyOffset());
            // --- Build the document
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            DocumentBuilder builder = factory.newDocumentBuilder();
            StringBuilder wsdl = new StringBuilder();
            wsdl.append(this.helpers.bytesToString(messageInfo.getResponse()).substring(rspInfo.getBodyOffset()));
            ByteArrayInputStream input = new ByteArrayInputStream(wsdl.toString().getBytes());
            Document doc = builder.parse(input);
            
            // --- Parse top level objects
            Element root = doc.getDocumentElement();
            stdout.print("\tNamespace is: "+root.getNamespaceURI());
            NodeList messages = doc.getElementsByTagName("wsdl:message");
            NodeList services = doc.getElementsByTagName("wsdl:service");
            NodeList bindings = doc.getElementsByTagName("wsdl:binding");
            NodeList portTypes = doc.getElementsByTagName("wsdl:portType");
            
            stdout.println("\n\t ("+Integer.toString(messages.getLength())+") Messages:");
            for(int i=0; i < messages.getLength(); i++){
                Node node = messages.item(i);
                stdout.println("\t"+node.getAttributes().getNamedItem("name").getNodeValue());
            }
            stdout.println("\t ("+Integer.toString(services.getLength())+") Services:");
            for(int i=0; i < services.getLength(); i++){
                Node node = services.item(i);
                stdout.println("\t"+node.getAttributes().getNamedItem("name").getNodeValue());
            }
            stdout.println("\t ("+Integer.toString(bindings.getLength())+") Bindings:");
            for(int i=0; i < bindings.getLength(); i++){
                Node node = bindings.item(i);
                stdout.println("\t"+node.getAttributes().getNamedItem("name").getNodeValue());
            }
            stdout.println("\t ("+Integer.toString(portTypes.getLength())+") PortType:");
            for(int i=0; i < portTypes.getLength(); i++){
                Node node = portTypes.item(i);
                stdout.println("\t"+node.getAttributes().getNamedItem("name").getNodeValue());
            }

        } catch (ParserConfigurationException | SAXException | IOException ex) {
            Logger.getLogger(BurpExtender.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

}

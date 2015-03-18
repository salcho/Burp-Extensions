package burp;

import java.io.PrintWriter;

/**
 *
 * @author salcho
 */
public class BurpExtender implements IBurpExtender{

    private PrintWriter stdout;
    private PrintWriter stderr;
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        
        // set our extension name
        callbacks.setExtensionName("SWFReplace");
        
        // obtain our output and error streams
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);
        
        callbacks.registerContextMenuFactory(new SWFMenu(callbacks));
    }
    
}

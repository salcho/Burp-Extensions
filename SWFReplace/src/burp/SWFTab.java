package burp;

import java.awt.Component;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JButton;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;


/**
 *
 * @author salcho
 */
public class SWFTab implements IMessageEditorController, ActionListener, ITab{

    private IMessageEditor editor;
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private boolean chosen;
    private File swf;
    private IHttpRequestResponse req;
    JSplitPane splitPane;
    
    public SWFTab(IBurpExtenderCallbacks callbacks, IHttpRequestResponse req){
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        // Have we chosen the new SWF
        this.chosen = false;
        // Keep track of this message
        this.req = req;
        
        // Create very simple UI Tab
        splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        JPanel panel = new JPanel(new GridLayout(0,2));
        
        // Top pane
        panel.add(new JLabel("Choose new SWF file"));
        JButton button = new JButton("Browse");
        button.setActionCommand("browse");
        button.addActionListener(this);
        panel.add(button);
        panel.add(new JLabel("Click to run -> "));
        button = new JButton("Run");
        button.setActionCommand("run");
        button.addActionListener(this);
        panel.add(button);
        panel.add(new JLabel("Close tab -> "));
        button = new JButton("Close");
        button.setActionCommand("close");
        button.addActionListener(this);
        panel.add(button);
        splitPane.setTopComponent(panel);
        
        // Bottom pane
        JTabbedPane tab = new JTabbedPane();
        editor = callbacks.createMessageEditor(SWFTab.this, true);
        tab.add("Request", editor.getComponent());
        tab.add("Response", editor.getComponent());
        splitPane.setBottomComponent(tab);
        
        callbacks.customizeUiComponent(splitPane);
        callbacks.addSuiteTab(SWFTab.this);
        
    }

    @Override
    public void actionPerformed(ActionEvent ae) {
        String action = ae.getActionCommand();
        // Close tab
        if(action.equals("close")){
            callbacks.removeSuiteTab(this);
        // Browse for file
        }else if(action.equals("browse")){
            JFileChooser chooser = new JFileChooser();
            int ret;
            ret = chooser.showOpenDialog(splitPane);
            if(ret == JFileChooser.APPROVE_OPTION){
                swf = chooser.getSelectedFile();
                this.chosen = true;
            }
        // Set our message to be the new SWF
        }else if(action.equals("run")){
            if(!this.chosen){
                Object[] opt = {"OK"};
                JOptionPane.showOptionDialog(splitPane, "You have not chosen a new SWF file!", "SwfIntercept", JOptionPane.OK_OPTION, JOptionPane.WARNING_MESSAGE, null, opt, opt[0]);
            }else{
                replace();
                /* Content-Type: application/x-shockwave-flash */
            }
        }
            
        
    }

    @Override
    public String getTabCaption() {
        return "SWFIntercept";
    }

    @Override
    public Component getUiComponent() {
        return splitPane;
    }
    
    public void replace(){
        // Copy request exactly as it was
        IRequestInfo info = helpers.analyzeRequest(req);
        byte[] message = helpers.buildHttpMessage(info.getHeaders(), this.req.getRequest());
        editor.setMessage(message, true);
    }

    @Override
    public IHttpService getHttpService() {
        return this.helpers.buildHttpService(this.req.getHttpService().getHost(), this.req.getHttpService().getPort(), this.req.getHttpService().getProtocol());
    }

    @Override
    public byte[] getRequest() {
        return editor.getMessage();
    }

    // Modify this method so that it returns a modified response
    // all original cookies, flash parameters, enabled/disabled buttons etc. 
    // will come into play when the browser loads this o.O
    // Modify SWF with JPEX!
    @Override
    public byte[] getResponse() {
        byte[] rsp = null;
        try {
            byte[] body = Files.readAllBytes(this.swf.toPath());
            IResponseInfo rspInfo = helpers.analyzeResponse(req.getResponse());
            rsp = helpers.buildHttpMessage(rspInfo.getHeaders(), body);
        } catch (IOException ex) {
            Logger.getLogger(SWFTab.class.getName()).log(Level.SEVERE, null, ex);
        }
        return rsp;
    }
    
    
}

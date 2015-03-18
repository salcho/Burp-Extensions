package burp;

import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JMenuItem;

/**
 *
 * @author salcho
 */
public class SWFMenu implements IContextMenuFactory{

    private IBurpExtenderCallbacks callbacks;
    private SWFTab tab;
    
    public SWFMenu(IBurpExtenderCallbacks callbacks){
        this.callbacks = callbacks;
    }
    
    @Override
    public List<JMenuItem> createMenuItems(final IContextMenuInvocation invocation) {
        List<JMenuItem> list = new ArrayList<JMenuItem>();
        JMenuItem item = new JMenuItem("SWFReplace this");
        
        MouseListener ml = new MouseListener() {

            @Override
            public void mouseClicked(MouseEvent me) {
                //nop
            }

            @Override
            public void mousePressed(MouseEvent me) {
                tab = new SWFTab(callbacks, invocation.getSelectedMessages()[0]);
            }

            @Override
            public void mouseReleased(MouseEvent me) {
                //nop
            }

            @Override
            public void mouseEntered(MouseEvent me) {
                //nop
            }

            @Override
            public void mouseExited(MouseEvent me) {
                //nop
            }
        };
        item.addMouseListener(ml);
        list.add(item);
        return list;
    }
    
}

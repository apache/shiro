package org.jsecurity.samples.spring.ui;

import org.jsecurity.authz.AuthorizationException;
import org.jsecurity.samples.spring.DefaultSampleManager;
import org.jsecurity.samples.spring.SampleManager;
import org.springframework.core.io.ClassPathResource;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;

/**
 * Insert JavaDoc here.
 */
public class WebStartView implements ActionListener {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    private SampleManager sampleManager;
    private JTextField valueField;
    private JButton saveButton;
    private JButton refreshButton;
    private JButton secureMethod1Button;
    private JButton secureMethod2Button;
    private JFrame frame;

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/


    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/
    public void setSampleManager(SampleManager sampleManager) {
        this.sampleManager = sampleManager;
    }

    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/
    public void init() throws IOException {
        ClassPathResource resource = new ClassPathResource( "webstartTitle.gif" );
        ImageIcon icon = new ImageIcon( resource.getURL() );
        JLabel logo = new JLabel( icon );

        valueField = new JTextField( 20 );
        updateValueLabel();

        saveButton = new JButton( "Save Value" );
        saveButton.addActionListener( this );

        refreshButton = new JButton( "Refresh Value" );
        refreshButton.addActionListener( this );

        JPanel valuePanel = new JPanel( new FlowLayout( FlowLayout.CENTER ) );
        valuePanel.add( valueField );
        valuePanel.add( saveButton );
        valuePanel.add( refreshButton );

        secureMethod1Button = new JButton( "Method #1" );
        secureMethod1Button.addActionListener( this );

        secureMethod2Button = new JButton( "Method #2" );
        secureMethod2Button.addActionListener( this );

        JPanel methodPanel = new JPanel( new FlowLayout( FlowLayout.CENTER ) );
        methodPanel.add( secureMethod1Button );
        methodPanel.add( secureMethod2Button );

        frame = new JFrame( "JSecurity Sample Application" );
        frame.setSize( 300, 200 );

        Container panel = frame.getContentPane();
        panel.setLayout( new BorderLayout() );
        panel.add( logo, BorderLayout.NORTH );
        panel.add( valuePanel, BorderLayout.CENTER );
        panel.add( methodPanel, BorderLayout.SOUTH );

        frame.setVisible( true );
        frame.addWindowListener( new WindowAdapter() {
            public void windowClosing(WindowEvent e) {
                System.exit(0);
            }
        } );
    }

    private void updateValueLabel() {
        valueField.setText( sampleManager.getValue() );
    }

    public void actionPerformed(ActionEvent e) {
        try {

            if( e.getSource() == saveButton ) {
                sampleManager.setValue( valueField.getText() );

            } else if( e.getSource() == refreshButton ) {
                updateValueLabel();

            } else if( e.getSource() == secureMethod1Button ) {
                sampleManager.secureMethod1();
                JOptionPane.showMessageDialog( frame, "Method #1 successfully called.", "Success", JOptionPane.INFORMATION_MESSAGE );

            } else if( e.getSource() == secureMethod2Button ) {
                sampleManager.secureMethod2();
                JOptionPane.showMessageDialog( frame, "Method #2 successfully called.", "Success", JOptionPane.INFORMATION_MESSAGE );

            } else {
                throw new RuntimeException( "Unexpected action event from source: " + e.getSource() );
            }

        } catch (AuthorizationException ae) {
            JOptionPane.showMessageDialog( frame, "Unauthorized to perform action: " + ae.getMessage(), "Unauthorized", JOptionPane.WARNING_MESSAGE );
        }
    }

    public static void main(String[] args) throws IOException {
        WebStartView test = new WebStartView();
        test.setSampleManager( new DefaultSampleManager() );
        test.init();
    }
}

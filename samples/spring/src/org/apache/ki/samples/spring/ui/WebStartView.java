/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.ki.samples.spring.ui;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import javax.swing.*;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.io.ClassPathResource;

import org.apache.ki.authz.AuthorizationException;
import org.apache.ki.samples.spring.DefaultSampleManager;
import org.apache.ki.samples.spring.SampleManager;


/**
 * Simple web start application that helps to demo single sign-on and
 * remoting authorization using Apache Ki.  The injected <tt>SampleManager</tt>
 * is hosted by the Spring sample web application and remotely invoked
 * when the buttons in this view are clicked.
 *
 * @author Jeremy Haile
 * @since 0.1
 */
public class WebStartView implements ActionListener, InitializingBean {

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
    private JButton secureMethod3Button;
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
    public void afterPropertiesSet() throws Exception {
        ClassPathResource resource = new ClassPathResource("logo.png");
        ImageIcon icon = new ImageIcon(resource.getURL());
        JLabel logo = new JLabel(icon);

        valueField = new JTextField(20);
        updateValueLabel();

        saveButton = new JButton("Save Value");
        saveButton.addActionListener(this);

        refreshButton = new JButton("Refresh Value");
        refreshButton.addActionListener(this);

        JPanel valuePanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        valuePanel.add(valueField);
        valuePanel.add(saveButton);
        valuePanel.add(refreshButton);

        secureMethod1Button = new JButton("Method #1");
        secureMethod1Button.addActionListener(this);

        secureMethod2Button = new JButton("Method #2");
        secureMethod2Button.addActionListener(this);

        secureMethod3Button = new JButton("Method #3");
        secureMethod3Button.addActionListener(this);

        JPanel methodPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        methodPanel.add(secureMethod1Button);
        methodPanel.add(secureMethod2Button);
        methodPanel.add(secureMethod3Button);

        frame = new JFrame("Apache Ki Sample Application");
        frame.setSize(500, 200);

        Container panel = frame.getContentPane();
        panel.setLayout(new BorderLayout());
        panel.add(logo, BorderLayout.NORTH);
        panel.add(valuePanel, BorderLayout.CENTER);
        panel.add(methodPanel, BorderLayout.SOUTH);

        frame.setVisible(true);
        frame.addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent e) {
                System.exit(0);
            }
        });
    }

    private void updateValueLabel() {
        valueField.setText(sampleManager.getValue());
    }

    public void actionPerformed(ActionEvent e) {
        try {

            if (e.getSource() == saveButton) {
                sampleManager.setValue(valueField.getText());

            } else if (e.getSource() == refreshButton) {
                updateValueLabel();

            } else if (e.getSource() == secureMethod1Button) {
                sampleManager.secureMethod1();
                JOptionPane.showMessageDialog(frame, "Method #1 successfully called.", "Success", JOptionPane.INFORMATION_MESSAGE);

            } else if (e.getSource() == secureMethod2Button) {
                sampleManager.secureMethod2();
                JOptionPane.showMessageDialog(frame, "Method #2 successfully called.", "Success", JOptionPane.INFORMATION_MESSAGE);
            } else if (e.getSource() == secureMethod3Button) {
                sampleManager.secureMethod3();
                JOptionPane.showMessageDialog(frame, "Method #3 successfully called.", "Success", JOptionPane.INFORMATION_MESSAGE);

            } else {
                throw new RuntimeException("Unexpected action event from source: " + e.getSource());
            }

        } catch (AuthorizationException ae) {
            JOptionPane.showMessageDialog(frame, "Unauthorized to perform action: " + ae.getMessage(), "Unauthorized", JOptionPane.WARNING_MESSAGE);
        }
    }

    public static void main(String[] args) throws Exception {
        WebStartView test = new WebStartView();
        test.setSampleManager(new DefaultSampleManager());
        test.afterPropertiesSet();
    }


}

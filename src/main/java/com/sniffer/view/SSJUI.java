package com.sniffer.view;

import com.sniffer.handle.SSJPackageParser;
import com.sniffer.handle.SSJPackageCatcher;
import com.sniffer.handle.SSJInfo;
import com.sniffer.hardware.SSJNetCard;

import com.sniffer.handle.SSJPacketMatch;

import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;
import org.junit.Test;
import org.jfree.chart.ChartPanel;
import javax.swing.*;
import javax.swing.plaf.metal.MetalPopupMenuSeparatorUI;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.JTableHeader;
import java.awt.*;
import java.awt.event.*;
import java.io.FileOutputStream;
import java.text.DateFormat;
import java.text.DecimalFormat;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.List;

public class SSJUI extends JFrame {
    //菜单条
	public static JMenuBar jMenuBar;
    //菜单
    JMenu  jMenu0, jMenu1, jMenu2, jMenu3, jMenu4;
    //菜单项
    JMenuItem[] jMenuItems;
  //协议过滤菜单条目
    JMenuItem mi_startCap, mi_endCap;
    //协议过滤菜单条目
    JMenuItem item1, item2, item3, item4, item5, item6, item7;
    //端口过滤菜单条目
    JMenuItem item11, item12;
    //IP过滤菜单条目
    JMenuItem item21, item22;
    //流追踪、重置
    JPopupMenu popupMenu;
    JMenuItem menuItem_IPProt,menuItem_ProId;
    JButton resetButton,aboutButton;
    //容器
    JPanel jPanel;
    //滚动条
    JScrollPane jScrollPane;
    //表格
    JTable jTable;
    JTextArea textArea_1;
    //表头内容
    public static JPanel jp_tuxingArea;
    public static DefaultListModel lItems = new DefaultListModel();
	private JList list = new JList(lItems);
    final String[] head = new String[]{
            "时间", "源IP/MAC", "目的IP/MAC","源端口","目的端口","协议", "长度","进程ID"
    };
    //表模型
    DefaultTableModel tableModel,myTableModel;
    //表内容
    Object[][] DataList = {};
    //处理信息
    SSJInfo infoHandle;

    //UI部分
    public SSJUI() {
        //标题设置
        this.setTitle("SSJ-Sniffer");
        //起始坐标、长宽
        this.setBounds(250, 150, 900, 600);
        //菜单条
        jMenuBar = new JMenuBar();
        
        // “抓包”菜单
        jMenu0 = new JMenu("  抓包  ");
        jMenu0.setFont(new Font("", Font.BOLD, 20));
        
        // “开始抓包”菜单项
        mi_startCap = new JMenuItem(" 开始抓包 ");
        mi_startCap.setFont(new Font("", Font.BOLD, 20));
		jMenu0.add(mi_startCap);
        		
        // “结束抓包”菜单项
		mi_endCap = new JMenuItem(" 结束抓包 ");
		mi_endCap.setFont(new Font("", Font.BOLD, 20));
		jMenu0.add(mi_endCap);

        //根据网卡过滤
		jMenu1 = new JMenu("  网卡  ");
        //设置字体
        jMenu1.setFont(new Font("", Font.BOLD, 20));
        //根据协议过滤
        jMenu2 = new JMenu("  协议  ");
        //设置字体
        jMenu2.setFont(new Font("", Font.BOLD, 20));
        //根据端口过滤
        jMenu3 = new JMenu("  端口  ");
        //设置字体
        jMenu3.setFont(new Font("", Font.BOLD, 20));
        //根据端口过滤
        jMenu4 = new JMenu("  ip  ");
        //设置字体
        jMenu4.setFont(new Font("", Font.BOLD, 20));
        //关于我们按钮
        aboutButton = new JButton(" 关于我们 ");
        //设置字体
        aboutButton.setFont(new Font("", Font.BOLD, 20));  
        item1 = new JMenuItem(" Ethernet ");
        //设置字体
        item1.setFont(new Font("", Font.BOLD, 20));
        item2 = new JMenuItem(" IP ");
        //设置字体
        item2.setFont(new Font("", Font.BOLD, 20));
        item3 = new JMenuItem(" ICMP ");
        //设置字体
        item3.setFont(new Font("", Font.BOLD, 20));
        item4 = new JMenuItem(" ARP ");
        //设置字体
        item4.setFont(new Font("", Font.BOLD, 20));
        item5 = new JMenuItem(" UDP ");
        //设置字体
        item5.setFont(new Font("", Font.BOLD, 20));
        item6 = new JMenuItem(" TCP ");
        //设置字体
        item6.setFont(new Font("", Font.BOLD, 20));
        item7 = new JMenuItem(" HTTP ");
        //设置字体
        item7.setFont(new Font("", Font.BOLD, 20));
        //加入协议过滤菜单选项
        jMenu2.add(item1);
        jMenu2.add(item2);
        jMenu2.add(item3);
        jMenu2.add(item4);
        jMenu2.add(item5);
        jMenu2.add(item6);
        jMenu2.add(item7);

        item11 = new JMenuItem(" 源端口 ");
        item11.setFont(new Font("", Font.BOLD, 20));

        item12 = new JMenuItem(" 目的端口 ");
        item12.setFont(new Font("", Font.BOLD, 20));
        //加入端口过滤菜单选项
        jMenu3.add(item11);
        jMenu3.add(item12);

        item21 = new JMenuItem(" 源IP地址 ");
        item21.setFont(new Font("", Font.BOLD, 20));

        item22 = new JMenuItem(" 目的IP地址 ");
        item22.setFont(new Font("", Font.BOLD, 20));

        //加入IP地址过滤菜单选项
        jMenu4.add(item21);
        jMenu4.add(item22);



        //重置按钮
        resetButton = new JButton(" 重置 ");
        //设置字体
        resetButton.setFont(new Font("", Font.BOLD, 20));
    
        //将菜单添加到菜单条上
        jMenuBar.add(jMenu0);
        jMenuBar.add(jMenu1);
        jMenuBar.add(jMenu2);
        jMenuBar.add(jMenu3);
        jMenuBar.add(jMenu4);

        jMenuBar.add(resetButton);
        jMenuBar.add(aboutButton);
        //菜单条设置
        setJMenuBar(jMenuBar);
        //表设置
        tableModel = new DefaultTableModel(DataList, head);
        //初始化表，设置所有行列无法编辑
        jTable = new JTable(tableModel) {
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        // 设置表格的大小
        jTable.setPreferredScrollableViewportSize(new Dimension(600, 30));
        // 创建表格标题对象
        JTableHeader head = jTable.getTableHeader();
        // 设置表头大小
        head.setPreferredSize(new Dimension(head.getWidth(), 30));
        // 设置表格字体
        head.setFont(new Font("楷体", Font.PLAIN, 16));
        //设置每行的高度为30
        jTable.setRowHeight(30);
        // 设置相邻两行单元格的距离
        jTable.setRowMargin(5);
        // 设置可否被选择.默认为false
        jTable.setRowSelectionAllowed(true);
        // 设置所选择行的背景色
        jTable.setSelectionBackground(Color.green);
        // 设置所选择行的前景色
        jTable.setSelectionForeground(Color.blue);
        // 是否显示网格线
        jTable.setShowGrid(true);
        //启动布局管理器
        jTable.doLayout();
        popupMenu = new JPopupMenu();
        menuItem_IPProt = new JMenuItem("基于IP和Port的TCP流跟踪");
        popupMenu.add(menuItem_IPProt);
        menuItem_ProId = new JMenuItem("基于进程的TCP流跟踪");
        popupMenu.add(menuItem_ProId);
        //新建滚动条
        jTable.scrollRectToVisible(jTable.getCellRect(jTable.getRowCount()-1,0,true));
        jScrollPane = new JScrollPane(jTable);
        //网格布局
        jPanel = new JPanel(new GridLayout(0, 1));
        //容器尺寸
        jPanel.setPreferredSize(new Dimension(900, 600));
        //容器背景
        jPanel.setBackground(Color.black);
        //设置滚动条
        jPanel.add(jScrollPane);
        //加入内容
        setContentPane(jPanel);
        
        JPanel jp_showArea = new JPanel();
		jp_showArea.setBackground(new Color(175, 238, 238));
		jp_showArea.setBounds(0, 455, 869, 206);
		getContentPane().add(jp_showArea);
		jp_showArea.setLayout(null);
		// 下左部分的文字区域，文字的方式显示统计结果
		JPanel jp_wordArea = new JPanel();
		jp_wordArea.setBounds(40, 10, 320, 186);
		jp_showArea.add(jp_wordArea);
		jp_wordArea.setLayout(null);

		// 文本域
		textArea_1 = new JTextArea();
		textArea_1.setFont(new Font("Microsoft YaHei UI", Font.PLAIN, 15));
		textArea_1.setEditable(false);
		textArea_1.setBounds(0, 0, 339, 186);
		jp_wordArea.add(textArea_1);
//		li.setJta_totalWord(textArea_1);

		// 下右部分的图形区域，图形的方式显示统计结果
		jp_tuxingArea = new JPanel();
		jp_tuxingArea.setBounds(374, 10, 485, 186);
		jp_showArea.add(jp_tuxingArea);
		jp_tuxingArea.setLayout(new BorderLayout(0, 0));

		// 下面是画图表的部分
//		 ChartPanel chartPanel = new ChartPanel( barChart );        
//	     chartPanel.setPreferredSize(new java.awt.Dimension( 560 , 367 ) ); 
//	     jp_tuxingArea.add(chartPanel);

		// 下最左部分的“统计区”文字显示
		JLabel lblNewLabel = new JLabel("<html>统<br/>计<br/>区<br/></html>");
		lblNewLabel.setFont(new Font("宋体", Font.BOLD | Font.ITALIC, 20));
		lblNewLabel.setBounds(10, 10, 26, 186);
		jp_showArea.add(lblNewLabel);
        
        pack();
        //显示设置
        setResizable(false);
        setVisible(true);
        //点击进程结束
        addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent e) {
                System.exit(0);
            }
        });
    }

    ///////////////////////////////////////////////////////////////////////////////////////
    //所有网卡列表
    List<PcapIf> allDevice;
    //抓包类
    SSJPackageCatcher packageCatcher;

    ////////////////////////////////////////////////////////////////////////////////////
    //数据填充
    @Test
    public void dataInjection() {
        //获取所有显卡
        allDevice = new SSJNetCard().getAllDevice();
        //动态初始化条目
        jMenuItems = new JMenuItem[allDevice.size()];
        int i = 0;
        //遍历网卡：显示网卡编号和描述信息
        for (PcapIf device : allDevice) {
            String description = (device.getDescription() != null) ? device.getDescription()
                    : "No description available";
            jMenuItems[i] = new JMenuItem("#" + i + ": " + device.getName() + "["
                    + description + "]");
            //字体设置
            jMenuItems[i].setFont(new Font("", Font.BOLD, 15));
            jMenu1.add(jMenuItems[i]);
            jMenuItems[i].addActionListener(new CardActionListener(device));
            i++;
        }
        //初始化抓包类
        packageCatcher = new SSJPackageCatcher();
        //初始化处理器信息
        infoHandle = new SSJInfo();
        infoHandle.setTableModel(tableModel);
        //item1绑定事件
        jTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                showPopup(e);
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                showPopup(e);
            }
            private void showPopup(MouseEvent e){
                if(e.isPopupTrigger()){
                    int row = jTable.rowAtPoint(e.getPoint());
                    if(row!=-1){
                        //选择该行
                        jTable.setRowSelectionInterval(row,row);

                        //弹出菜单
                        popupMenu.show(e.getComponent(),e.getX(),e.getY());
                    }
                }
            }
        });
        mi_startCap.addActionListener(
                new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                    	SSJPackageCatcher.startCapturePacket();
                    	packageCatcher.setInfoHandle(infoHandle);
                        capThread = new Thread(packageCatcher);
                        capThread.start();   //开启抓包线程
                        String cmd;
                        cmd = e.getActionCommand();
                    	System.out.println(cmd);
                    }
                });
        mi_endCap.addActionListener(
                new ActionListener() {
                	private String message;
                	public JTextArea jta_totalWord = textArea_1; 
                	private DecimalFormat df = new DecimalFormat("0.0000");
                    public void setJta_totalWord(JTextArea jta_totalWord) {
                		this.jta_totalWord = jta_totalWord;
                	}                   
                    @Override
                    public void actionPerformed(ActionEvent e) {
                    	SSJPackageCatcher.stopCapturePacket();
                    	System.out.println("111");
                    	jta_totalWord.setText("");
            			message = "Tcp:\t" + SSJPacketMatch.numberOfTcp + "包\t" + df.format(SSJPacketMatch.totalOfTcp) + "KB\n"
            					+ "Udp:\t" + SSJPacketMatch.numberOfUdp + "包\t" + df.format(SSJPacketMatch.totalOfUdp) + "KB\n"
            					+ "Icmp:\t" + SSJPacketMatch.numberOfIcmp + "包\t" + df.format(SSJPacketMatch.totalOfIcmp) + "KB\n"
            					+ "Arp:\t" + SSJPacketMatch.numberOfArp + "包\t" + df.format(SSJPacketMatch.totalOfArp) + "KB\n"
            					+ "广播包:\t" + SSJPacketMatch.numberOfWideSpread + "包\t" + df.format(SSJPacketMatch.totalOfSpread)
            					+ "KB\n" + "总流量:\t" + SSJPacketMatch.numberOfPacket + "包\t" + df.format(SSJPacketMatch.totalOfIp)
            					+ "MB";
            			jta_totalWord.append(message);
                    	SSJBarChart bc = new SSJBarChart();
            			bc.showChart();
                    }
                });
        item1.addActionListener(
                new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e3) {
                        infoHandle.setFilterProtocol("Ethernet II");
                        infoHandle.ShowAfterFilter();
                    }
                });
        item2.addActionListener(
                new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e3) {
                        infoHandle.setFilterProtocol("IP");
                        infoHandle.ShowAfterFilter();
                    }
                });
        item3.addActionListener(
                new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e3) {
                        infoHandle.setFilterProtocol("ICMP");
                        infoHandle.ShowAfterFilter();
                    }
                });
        item4.addActionListener(
                new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e3) {
                        infoHandle.setFilterProtocol("ARP");
                        infoHandle.ShowAfterFilter();
                    }
                });
        item5.addActionListener(
                new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e3) {
                        infoHandle.setFilterProtocol("UDP");
                        infoHandle.ShowAfterFilter();
                        System.out.println("UDP");
                    }
                });
        item6.addActionListener(
                new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e3) {
                        infoHandle.setFilterProtocol("TCP");
                        infoHandle.ShowAfterFilter();
                    }
                });
        item7.addActionListener(
                new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e3) {
                        infoHandle.setFilterProtocol("HTTP");
                        infoHandle.ShowAfterFilter();
                    }
                });
        item11.addActionListener(
                new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e3) {
                        String srcPort = JOptionPane.showInputDialog("请输入源端口，以筛选数据包：");
                        if (srcPort == null) srcPort = "";
                        infoHandle.setFilterSrcPort(srcPort);
                        infoHandle.ShowAfterFilter();
                    }
                });
        item12.addActionListener(
                new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e3) {
                        String desPort = JOptionPane.showInputDialog("请输入目的端口，以筛选数据包：");
                        if (desPort == null) desPort = "";
                        infoHandle.setFilterDesPort(desPort);
                        infoHandle.ShowAfterFilter();
                    }
                });
        item21.addActionListener(
                new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        String fsip = JOptionPane.showInputDialog("请输入源IP，以筛选数据包：");
                        if (fsip == null) fsip = "";
                        infoHandle.setFilterSrcIp(fsip);
                        infoHandle.ShowAfterFilter();
                    }
                });
        item22.addActionListener(
                new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        String fdip = JOptionPane.showInputDialog("请输入目的IP，以筛选数据包：");
                        if (fdip == null) fdip = "";
                        infoHandle.setFilterDesIp(fdip);
                        infoHandle.ShowAfterFilter();
                    }
                });
        menuItem_IPProt.addActionListener(
                new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        int row = jTable.getSelectedRow();
                        //获取选择行的关键信息用于跟踪
                       
                        String srcIp = (String) jTable.getValueAt(row,1);
                        String desIp = (String) jTable.getValueAt(row,2);
                        String srcPort = (String) jTable.getValueAt(row,3);
                        String desPort = (String) jTable.getValueAt(row,4);
                        JFrame myFrame = new JFrame("基于IP和Port的TCP流跟踪");
                        myFrame.setSize(1000,600);
                        Object[][] myDataList = {};
                        myTableModel = new DefaultTableModel(myDataList,head);

                        infoHandle.setMyTableModel(myTableModel);
                        infoHandle.showAfterTrace_IPProt(srcIp,desIp,srcPort,desPort);
                        System.out.println("总行数："+myTableModel.getColumnCount());
                        JTable newTable = new JTable();
                        newTable.setModel(myTableModel);
                        myFrame.getContentPane().add(new JScrollPane(newTable));
                        myFrame.setVisible(true);
                    }
                });
        menuItem_ProId.addActionListener(
                new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        int row = jTable.getSelectedRow();
                        //获取选择行的关键信息用于跟踪
                        String ProcessId = (String) jTable.getValueAt(row,7);
                        JFrame myFrame = new JFrame("基于进程的TCP流跟踪");
                        myFrame.setSize(1000,600);
                        Object[][] myDataList = {};
                        myTableModel = new DefaultTableModel(myDataList,head);

                        infoHandle.setMyTableModel(myTableModel);
                        infoHandle.showAfterTrace_ProId(ProcessId);
                        System.out.println("总行数："+myTableModel.getColumnCount());
                        JTable newTable = new JTable();
                        newTable.setModel(myTableModel);
                        myFrame.getContentPane().add(new JScrollPane(newTable));
                        myFrame.setVisible(true);
                    }
                });
        resetButton.addActionListener(
                new ActionListener() {
                	public JTextArea jta_totalWord = textArea_1; 
                    public void actionPerformed(ActionEvent e) {
                    	SSJPackageCatcher.stopCapturePacket();
                    	SSJPackageCatcher.clearPacket();
                        infoHandle.setFilterSrcPort("");
                        infoHandle.setFilterDesPort("");
                        infoHandle.setFilterProtocol("");
                        infoHandle.setFilterDesIp("");
                        infoHandle.setFilterSrcIp("");
                        infoHandle.clearAllPackets();
                        infoHandle.ShowAfterFilter();
//                        MyPacketMatch.numberOfPacket = 0;// 数据包数量
//                    	MyPacketMatch.totalOfIcmp = 0; // 统计icmp数据流量
//                    	MyPacketMatch.totalOfTcp = 0; // 统计tcp数据流量
//                    	MyPacketMatch.totalOfUdp = 0; // 统计udp数据流量
//                    	MyPacketMatch.totalOfArp = 0; // 统计arp数据流量
//                    	MyPacketMatch.totalOfIp = 0; // 统计ip数据流量
//                    	MyPacketMatch.totalOfSpread = 0; // 统计广播数据流量
//                    	MyPacketMatch.numberOfWideSpread = 0;// 统计广播包数量
//                    	MyPacketMatch.numberOfTcp = 0;// 统计tcp包数量
//                    	MyPacketMatch.numberOfUdp = 0;// 统计udp包数量
//                    	MyPacketMatch.numberOfIcmp = 0;// 统计icmp包数量
//                    	MyPacketMatch.numberOfArp = 0;// 统计arp包数量      
                    	jta_totalWord.setText("");
                    	SSJBarChart bc = new SSJBarChart();
            			bc.showChart();
                    }
                });
        jTable.addMouseListener(new MouseAdapter() {
            public void mouseClicked(MouseEvent ev) {
                if (ev.getClickCount() == 2) {
                    //获得选取行
                    int row = jTable.getSelectedRow();
                    //标题
                    JFrame frame = new JFrame("详细信息");
                    //画布
                    JPanel panel = new JPanel();
                    //文本区域大小
                    final JTextArea info = new JTextArea(32, 42);
                    //是否可编辑
                    info.setEditable(false);
                    info.setLineWrap(true);
                    info.setWrapStyleWord(true);
                    frame.add(panel);
                    //加滚动条
                    panel.add(new JScrollPane(info));
                    JButton save = new JButton("保存到本地");
                    //保存事件绑定
                    save.addActionListener(
                            new ActionListener() {
                                public void actionPerformed(ActionEvent e3) {
                                    String text = info.getText();
                                    Date date = new Date(System.currentTimeMillis());
                                    DateFormat df = new SimpleDateFormat("HH点mm秒ss");
                                    String name = df.format(date);
                                    try {//"src/saveFile/" + 
                                        FileOutputStream fos = new FileOutputStream("src/saveFile/" + name + ".txt");
                                        fos.write(text.getBytes());
                                        fos.close();
                                        JOptionPane.showMessageDialog(null, "文件保存成功，路径：" +"src/saveFile/" + name + ".txt", "成功",
                        						JOptionPane.INFORMATION_MESSAGE);
                                    } catch (Exception e) {
                                    	JOptionPane.showMessageDialog(null, "文件保存失败", "错误", JOptionPane.ERROR_MESSAGE);
                                        e.printStackTrace();
                                    }
                                }
                            });
                    //加入保存按钮并且设置
                    panel.add(save);
                    frame.setBounds(150, 150, 500, 600);
                    frame.setVisible(true);
                    frame.setResizable(false);
                    //获取数据包
                    ArrayList<PcapPacket> packetList = infoHandle.analyzePacketList;
                    //获得分析后的信息
                    Map<String, String> hm = new HashMap<String, String>();
                    PcapPacket packet = packetList.get(row);
                    SSJPackageParser packageAnalyzer = new SSJPackageParser(packet);
                    hm = packageAnalyzer.Analyzed();
                    info.append("                                       " + hm.get("协议") + "数据包" + "                               \n");
                    if (packet.hasHeader(Ethernet.ID)) {
                        info.append("------------------------------------------------------------------------------\n");
                        info.append("----------------------------Ethernet头信息：--------------------------\n");
                        info.append("------------------------------------------------------------------------------\n");
                        info.append("源MAC" + " : " + hm.get("源MAC") + "\n");
                        info.append("源MAC地址类型" + " : " + hm.get("源MAC地址类型") + "\n");
                        info.append("源主机传播方式" + " : " + hm.get("源主机传播方式") + "\n");
                        info.append("目的MAC" + " : " + hm.get("目的MAC") + "\n");
                        info.append("目的MAC地址类型" + " : " + hm.get("目的MAC地址类型") + "\n");
                        info.append("目的主机传播方式" + " : " + hm.get("目的主机传播方式") + "\n");
                    }
                    if (packet.hasHeader(Ip4.ID) || packet.hasHeader(Ip6.ID)) {
                        info.append("------------------------------------------------------------------------------\n");
                        info.append("-------------------------------IP头信息：-------------------------------\n");
                        info.append("------------------------------------------------------------------------------\n");
                        info.append("IP协议版本" + " : " + hm.get("IP协议版本") + "\n");
                        info.append("头长度" + " : " + packet.getCaptureHeader().wirelen() + "\n");
                        info.append("源IP4地址" + " : " + hm.get("源IP4") + "\n");
                        info.append("源IP6地址" + " : " + hm.get("源IP6") + "\n");
                        info.append("目的IP4地址" + " : " + hm.get("目的IP4") + "\n");
                        info.append("目的IP6地址" + " : " + hm.get("目的IP6") + "\n");
                        info.append("是否有其他切片" + " : " + hm.get("是否有其他切片") + "\n");
                    } else if (packet.hasHeader(new Arp())) {
                        info.append("------------------------------------------------------------------------------\n");
                        info.append("-------------------------------ARP头信息：------------------------------\n");
                        info.append("------------------------------------------------------------------------------\n");
                        Arp arp = packet.getHeader(new Arp());
                        info.append(arp + "\n");
                    }
                    if (packet.hasHeader(Tcp.ID)) {
                        info.append("------------------------------------------------------------------------------\n");
                        info.append("-------------------------------TCP头信息：------------------------------\n");
                        info.append("------------------------------------------------------------------------------\n");
                        info.append("源主机端口" + " : " + hm.get("源端口") + "\n");
                        info.append("目的主机端口" + " : " + hm.get("目的端口") + "\n");
                        info.append("是否有SYN标志位" + " : " + hm.get("Syn") + "\n");
                        info.append("是否有FIN标志位" + " : " + hm.get("Fin") + "\n");
                        info.append("Ack序号" + " : " + hm.get("Ack序号") + "\n");
                        info.append("Seq序号" + " : " + hm.get("Seq序号") + "\n");
                        info.append("是否使用http协议" + " : " + hm.get("是否使用http协议") + "\n");
                    } else if (packet.hasHeader(Udp.ID)) {
                        info.append("------------------------------------------------------------------------------\n");
                        info.append("-------------------------------UDP头信息：------------------------------\n");
                        info.append("------------------------------------------------------------------------------\n");
                        info.append("源主机端口" + " : " + hm.get("源端口") + "\n");
                        info.append("目的主机端口" + " : " + hm.get("目的端口") + "\n");
                    } else if (packet.hasHeader(new Icmp())) {
                        info.append("------------------------------------------------------------------------------\n");
                        info.append("-------------------------------ICMP头信息：-----------------------------\n");
                        info.append("------------------------------------------------------------------------------\n");
                        Icmp icmp = packet.getHeader(new Icmp());
                        info.append(icmp + "\n");
                    }
                    if (packet.hasHeader(Http.ID)) {
                        info.append("------------------------------------------------------------------------------\n");
                        info.append("-------------------------------HTTP头信息：-----------------------------\n");
                        info.append("------------------------------------------------------------------------------\n");
                        packageAnalyzer.handleHttp();
                        for (Map.Entry<String, String> me : packageAnalyzer.fieldMap.entrySet()) {
                            info.append(me.getKey() + " : " + me.getValue() + "\n");
                        }
                        for (Map.Entry<String, String> me : packageAnalyzer.httpParams.entrySet()) {
                            info.append(me.getKey() + " : " + me.getValue() + "\n");
                        }
                        info.append(packageAnalyzer.httpresult);
                    }

                    info.append("------------------------------------------------------------------------------\n");
                    info.append("原始数据包内容" + " : \n" + hm.get("包内容") + "\n");
                }
            }
        });
        aboutButton.addActionListener(
                new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                    	SSJAboutWin aw = new SSJAboutWin();
            			aw.showAboutWin();
                    }
                });
        
        //设置选择接口优先级，选择接口后才能开始抓包等其他操作
        jMenu0.setEnabled(false);
        jMenu2.setEnabled(false);
        jMenu3.setEnabled(false);
        jMenu4.setEnabled(false);
        resetButton.setEnabled(false);
        JOptionPane.showMessageDialog( null, "请先选择一个接口","嗅探器的首要操作",JOptionPane.INFORMATION_MESSAGE);

    }

    //表示整个抓包进程
    Thread capThread = null;
    //为每张网卡绑定响应事件
    private class CardActionListener implements ActionListener {
    	private String cmd;
        PcapIf device;
        CardActionListener(PcapIf device) {
            this.device = device;
        }
        public void actionPerformed(ActionEvent e) {
        	cmd = e.getActionCommand();
        	System.out.println(cmd);
        	packageCatcher.setDevice(device);
        	//选择接口后开放开始抓包等其他操作
        	jMenu0.setEnabled(true);
            jMenu2.setEnabled(true);
            jMenu3.setEnabled(true);
            jMenu4.setEnabled(true);
            resetButton.setEnabled(true);

        }
    }

    public static void main(String[] args) {
        SSJUI ssjUI = new SSJUI();
        ssjUI.dataInjection();
    }
}



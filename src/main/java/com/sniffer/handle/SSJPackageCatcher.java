package com.sniffer.handle;

import lombok.Getter;
import lombok.Setter;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import com.sniffer.view.SSJUI;


@Getter
@Setter
public class SSJPackageCatcher implements Runnable {
	private static boolean flag = true;//网卡设备使用标志位
    //要抓包的设备
    private PcapIf device;
    //处理器信息
    private SSJInfo infoHandle;
    //这个类是与 libpcap 和 winpcap 库实现中的原生 pcap_t 结构对等的Java类。
    // 它提供了Java 与libpcap 库方法的直接映射。
    static Pcap pcap;

    public SSJPackageCatcher() {
    }
    public void setDevice(PcapIf device2) {
    	device = device2;
		// TODO Auto-generated method stub
		
	}
    public void setInfoHandle(SSJInfo infoHandle2) {
    	infoHandle = infoHandle2;
		// TODO Auto-generated method stub
		
	}
    @Override
    public void run() {
        //打开选中的网卡设备，截断此大小的数据包
        int snapLen = Pcap.DEFAULT_JPACKET_BUFFER_SIZE;
        //网卡模式：混杂模式
        int promiscuous = Pcap.MODE_PROMISCUOUS; //截取模式为混杂模式
        //以毫秒为单位
        int timeout = 60 * 1000; //超时设置为60seconds
        //如果发生错误，它将保存一个错误字符串。 错误打开 Live 将返回 null
        StringBuilder errbuf = new StringBuilder();
        //抓包开启
        // openlive方法：这个方法打开一个和指定网络设备有关的，活跃的捕获器 

        // 参数：snaplen指定的是可以捕获的最大的byte数，
        // 如果 snaplen的值 比 我们捕获的包的大小要小的话，
        // 那么只有snaplen大小的数据会被捕获并以packet data的形式提供。
        // IP协议用16位来表示IP的数据包长度，所有最大长度是65535的长度
        // 这个长度对于大多数的网络是足够捕获全部的数据包的

        // 参数：flags promisc指定了接口是promisc模式的，也就是混杂模式，
        // 混杂模式是网卡几种工作模式之一，比较于直接模式：
        // 直接模式只接收mac地址是自己的帧，
        // 但是混杂模式是让网卡接收所有的，流过网卡的帧，达到了网络信息监视捕捉的目的

        // 参数：timeout 这个参数使得捕获报后等待一定的时间，来捕获更多的数据包，
        // 然后一次操作读多个包，不过不是所有的平台都支持，不支持的会自动忽略这个参数

        // 参数：errbuf pcap_open_live()失败返回NULL的错误信息，或者成功时候的警告信息   
        pcap = Pcap.openLive(device.getName(), snapLen, promiscuous, timeout, errbuf);   //打开连接,调用Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf)静态方法，返回一个Pcap对象。其中5个参数分别表示设备的系统名称（不是设备别名）、每次捕捉的数据量、捕捉方式、超时和错误信息缓冲区。
        if (pcap == null) {
            System.err.println("获取数据包失败：" + errbuf.toString());
            return;
        }
        //定义处理器
        SSJPcapHandler<Object> myPcapHandler = new SSJPcapHandler<Object>();
        // 捕获数据包计数
        int cnt = 1;
        while (SSJPackageCatcher.flag) {
            //每个数据包将被分派到抓包处理器Handler
            pcap.loop(cnt, myPcapHandler, infoHandle);
//            System.out.println("list的大小为：" + infoHandle.packetList.size());
        }
    }
    /**
	 * 开始抓包
	 */
	public static void startCapturePacket(){
		SSJPackageCatcher.flag = true;
	}
	/**
	 * 停止抓包
	 */
	public static void stopCapturePacket(){
		SSJPackageCatcher.flag = false;
	}
	
	/**
	 * 清空记录
	 */
	public static void clearPacket(){
		SSJPacketMatch.numberOfPacket=0;		
		SSJPacketMatch.numberOfArp=0;
		SSJPacketMatch.numberOfTcp=0;
		SSJPacketMatch.numberOfUdp=0;
		SSJPacketMatch.numberOfIcmp=0;
		SSJPacketMatch.numberOfWideSpread=0;
		SSJPacketMatch.hm.clear();
		SSJUI.lItems.clear();	
//		MyUI.CardActionListener.jta_totalWord.setText("");
	}

	
}


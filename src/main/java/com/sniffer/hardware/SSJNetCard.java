package com.sniffer.hardware;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;


/*
 * 抓包的工具类，偏于底层的抓包，接入jnetpcap的接口 负责网卡列表的获取、包的捕获、抓包程序的停止
 */
public class SSJNetCard {
    //获得网卡列表
	
    List<PcapIf> allDevice = new ArrayList<PcapIf>();

    StringBuilder errInfo = new StringBuilder();

    /**
	 * 用于获取设备的网卡适配器 部分代码参考jnetpcap官网案例1
	 * 
	 * @return Arrayist（网卡设备列表）
	 */
    @Test
    public List<PcapIf> getAllDevice() {
        //get card info
        int r = Pcap.findAllDevs(allDevice, errInfo);  //将所有本机网卡加入到alldevs的List<PcapIf>中,然后用户可以选择一个网卡进行监听

        if (r == Pcap.NOT_OK || allDevice.isEmpty()) {
            System.err.printf("Can’t read list of devices, error is %s", errInfo.toString());
            return allDevice;
        }
        System.out.println("Network devices found:");
        return allDevice;
    }
}


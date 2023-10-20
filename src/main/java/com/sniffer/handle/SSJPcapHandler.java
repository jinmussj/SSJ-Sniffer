package com.sniffer.handle;

import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

public class SSJPcapHandler<Object> implements PcapPacketHandler<Object> {
    SSJFilter filterUtils;
    @Override
    //这是典型的通过事件机制来实现处理数据包的方法。
    //每当Pcap嗅探到一个数据包后，就会调用用户之前绑定的分析器中的nextPacket方法进行处理。
    //注意这个方法是阻塞的，也就避免了潜在的同步问题。传进的JPacket参数包含了这个数据包中的所有信息，通过不同的内置Header分析器可以分析不同的协议。
    public void nextPacket(PcapPacket packet, Object infoHandle) {
        SSJInfo Info = (SSJInfo) infoHandle;
        if (packet != null) {
            //抓到的所有包都放入
            Info.packetList.add(packet);
            SSJPacketMatch mpm = SSJPacketMatch.getInstance();
    		
    		mpm.handlePacket(packet);
            //符合条件的包放入
            if(filterUtils.IsFilter(packet, Info.FilterProtocol, Info.FilterSrcIp, Info.FilterDesIp,Info.FilterSrcPort,Info.FilterDesPort)){
                Info.analyzePacketList.add(packet);
                Info.showTable(packet);
            }
        }
    }
}


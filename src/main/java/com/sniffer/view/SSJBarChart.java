package com.sniffer.view;

import java.awt.BorderLayout;
import com.sniffer.handle.SSJPacketMatch;
import org.jfree.chart.ChartFactory;
import org.jfree.chart.ChartPanel;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.plot.PlotOrientation;
import org.jfree.data.category.CategoryDataset;
import org.jfree.data.category.DefaultCategoryDataset;

/**
 * 生成统计柱状图的类
 *
 */
public class SSJBarChart {
	//柱状图对象
	public static JFreeChart barChart = ChartFactory.createBarChart("数据包统计结果", "数据包类型", "数量", createDataset(),
			PlotOrientation.HORIZONTAL, true, true, false);
	
	/**
	 * 数据集
	 * @return dataset
	 */
	private static CategoryDataset createDataset() {
		final String tcp = "TCP";
		final String udp = "UDP";
		final String arp = "ARP";
		final String icmp = "ICMP";
		final String widespread = "广播包";
		final String number = "包数量";
		final DefaultCategoryDataset dataset = new DefaultCategoryDataset();
		dataset.clear();
		dataset.addValue(SSJPacketMatch.numberOfTcp, tcp, number);
		dataset.addValue(SSJPacketMatch.numberOfUdp, udp, number);
		dataset.addValue(SSJPacketMatch.numberOfArp, arp, number);
		dataset.addValue(SSJPacketMatch.numberOfIcmp, icmp, number);
		dataset.addValue(SSJPacketMatch.numberOfWideSpread, widespread, number);
		// 遍历数据集中的所有内容
        for (Object rowKey : dataset.getRowKeys()) {
            for (Object columnKey : dataset.getColumnKeys()) {
                Number value = dataset.getValue((Comparable<?>) rowKey, (Comparable<?>) columnKey);
                System.out.println("Row Key: " + rowKey + ", Column Key: " + columnKey + ", Value: " + value);
            }
        }
		return dataset;
	}

	/**
	 * 显示图表
	 */
	public void showChart() {
		barChart = ChartFactory.createBarChart("数据包统计结果", "数据包类型", "数量", createDataset(),
				PlotOrientation.HORIZONTAL, true, true, false);
		ChartPanel myChart = new ChartPanel(barChart);
		System.out.println("222");
		// 从面板中删除所有组件
		SSJUI.jp_tuxingArea.removeAll();
        // 重新绘制面板
		SSJUI.jp_tuxingArea.revalidate();
		SSJUI.jp_tuxingArea.repaint();
		SSJUI.jp_tuxingArea.setLayout(new java.awt.BorderLayout()); //border布局
		
		SSJUI.jp_tuxingArea.add(myChart,BorderLayout.CENTER);
		SSJUI.jp_tuxingArea.validate();  //设置为生效
	}
}
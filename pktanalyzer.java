/*
 * packetanalyzer.java
 *
 * Version:
 *     $1.0$
 */

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;


/*
 * This program decodes the packets that are captured into various layers starting from Physical link layer.
 *
 * @author      Prasanna Mahesh Bhope
 */
public class pktanalyzer {
	
	public static StringBuilder convertToMac(int[] info, int start, int end) {
		StringBuilder Mac = new StringBuilder();
		for (int i = start; i < end; i++) {
			Mac.append(String.format("%02x%s", info[i], (i < end - 1) ? ":" : ""));		
		}
		return Mac;
	}
	
	
	public static long HexToDecimal(int info[], int start, int end) {
		String s = convertToMac(info, start, end).toString();
		s = s.replace(":", "");
		long identifyinDecimal = Long.parseLong(s, 16);
		return identifyinDecimal;
	}
	
	public static StringBuilder IPAddress(int info[], int start, int end) {
		StringBuilder ipaddr = new StringBuilder();
		for(int i = start; i < end; i++) {
			ipaddr = ipaddr.append(String.valueOf(info[i]) + ".");
		}
		return ipaddr;
	}
	
	public static String printData(String s) {
		int i = 0;
		String data1 = "";
		while(i <= s.length()-4) {
			data1 = data1 +" " +s.substring(i, i+4);
			i+=4;
		}
		return data1;
	}
	
	
	public static void etherInfo(int[] info, byte[] content) {
		System.out.println("ETHER:\t ----- Ether Header -----");
		System.out.println("ETHER:");
		System.out.println("ETHER:\t Packet size = "+info.length  +" bytes");
		System.out.println("ETHER:\t Destination = "+convertToMac(info, 0, 6));
		System.out.println("ETHER:\t Source\t     = "+convertToMac(info, 6, 12));
		String etherType = convertToMac(info, 12, 14).toString();
		if (etherType.equals("08:00")) {
			System.out.println("ETHER:\t Ethertype   = 0800 (IP)");
			System.out.println("ETHER:\t");
			IPinfo(info,content);
		}
		else if (etherType.equals("08:06")) {
			System.out.println("ETHER:\t Ethertype = 0806 (ARP)");
			System.out.println("ETHER:");
			ARPInfo(info);
		}
		
	}
	
public static void ARPInfo(int[] info) {
	System.out.println("ARP:\t ----- ARP Header -----");
	System.out.println("ARP:");
	long hardwareType = HexToDecimal(info, 14, 16);
	if(hardwareType == 1) System.out.println("ARP:\t Hardware type: "+"Ethernet " +"(" +hardwareType+")");
	String protocolType = "0x"+convertToMac(info, 16, 18).toString().replace(":", "");
	if(protocolType.equals("0x0800"))
		System.out.println("ARP:\t Protocol Type: IP  " +"("+protocolType+")");
	else
		System.out.println("ARP:\t Protocol Types: Unrecognized");
	System.out.println("ARP:\t Hardware size: "+HexToDecimal(info, 18, 19));
	System.out.println("ARP:\t Protocol size: "+HexToDecimal(info, 19, 20));
	long opcode = HexToDecimal(info, 20, 22);
	if(opcode == 1) System.out.println("ARP\t Opcode: Request " +"(" +opcode +")");
	else if (opcode ==2) System.out.println("ARP\t Opcode: Reply " +"(" +opcode +")");
	System.out.println("ARP:\t Sender MAC Address= "+convertToMac(info, 22, 28));
	System.out.println("ARP:\t Sender IP Address= "+IPAddress(info, 28, 32).toString().substring(0, IPAddress(info, 28, 32).toString().length()-1));
	System.out.println("ARP:\t Target MAC Address= "+convertToMac(info, 32, 38));
	System.out.println("ARP:\t Target IP Address= "+IPAddress(info, 38, 42).toString().substring(0, IPAddress(info, 38, 42).toString().length()-1));
	
	}
	
	public static void IPinfo(int[] info, byte[] content) {
		boolean TCPFlag = false; 
		boolean UDPFlag = false; 
		boolean ICMPFlag = false;
		System.out.println("IP:\t ----- IP Header -----");
		System.out.println("IP:");
		System.out.println("IP:\t Version: "+convertToMac(info, 14, 15).substring(0, 1));
		int headerLengthWord = Integer.parseInt(convertToMac(info, 14, 15).substring(1));
		int headerLength = headerLengthWord * 4;
		System.out.println("IP:\t Header Length = "+headerLength +" Bytes");
		System.out.println("IP:\t Differentiated Services Code Point: 0x"+content[15]); //15//to do
		
		byte ECN1st = (byte) ((content[15] >> 0) & 0x0F) ;
		byte ECN2nd = (byte) ((content[15] >>0) & 0x0F);
		if(ECN1st == 0 && ECN2nd == 0 ) System.out.println("IP:\t\t .... ..00  Non ECN-Capable Transport, Non-ECT ");
		if(ECN1st == 1 && ECN2nd == 0 ) System.out.println("IP:\t\t .... ..10  ECN Capable Transport, ECT(0) ");
		if(ECN1st == 0 && ECN2nd == 1 ) System.out.println("IP:\t\t .... ..01  ECN Capable Transport, ECT(1) ");
		if(ECN1st == 1 && ECN2nd == 1 ) System.out.println("IP:\t\t .... ..01  Congestion Encountered, CE. ");
		
		
		
		
		long totalLength = HexToDecimal(info, 16, 18); 
		System.out.println("IP:\t Total length = "+totalLength +" bytes");
		long identifyinDecimal = HexToDecimal(info, 18, 20);
		System.out.println("IP:\t Identification: "+identifyinDecimal);
		System.out.println("IP:\t Flags: "+"0x"+convertToMac(info, 20,21).toString().replace(":", "").substring(0,1));
		int hex = Integer.parseInt(convertToMac(info, 20, 21).toString(),16);
		String flags="0"+Integer.toBinaryString(hex); 
        if(Integer.toBinaryString(hex).charAt(0)=='1')
            System.out.println("IP:\t\t .1.. ....= do not fragment");
        else
            System.out.println("IP:\t\t .0.. ....= Ok to fragment");
        if(Integer.toBinaryString(hex).length()==1) 
        	System.out.println("IP:\t\t ..0. ....= last fragment");
        else {

        if(Integer.toBinaryString(hex).charAt(1)=='1')
            System.out.println("IP:\t\t ..1. ....= more fragments");
        else
            System.out.println("IP:\t\t ..0. ....= last fragment");
        }
        String fragOffset = "";
        if(Integer.toBinaryString(hex).length()==1)
        	fragOffset =fragOffset+flags.substring(1);
        else
        	fragOffset=fragOffset+flags.substring(3);
        System.out.println("IP:\t Fragment offset = "+fragOffset +" bytes");
		long ttl = HexToDecimal(info, 22, 23);
		System.out.println("IP:\t Time to live: "+ttl +" seconds/hops");
		int protocol = info[23];
		switch(protocol) {
			case 6:
				System.out.println("IP:\t Protocol:" +protocol +" (TCP)");
				TCPFlag = true;
				break;
				
			case 17:
				System.out.println("IP:\t Protocol:" +protocol +" (UDP)");
				UDPFlag = true;
				break;
			
			case 1:
				System.out.println("IP:\t Protocol:" +protocol +" (ICMP)");
				ICMPFlag = true;
				break;
			
			default:
				System.out.println("IP:\t Protocol not available in the program");
		}
		String checksome = "0x"+convertToMac(info, 24, 26).toString().replace(":", "");
		System.out.println("IP:\t Header Checksome: " +checksome);
		System.out.println("IP:\t Source address: "+IPAddress(info, 26, 30).toString().substring(0, IPAddress(info, 26, 30).toString().length()-1));
		System.out.println("IP:\t Destination address: "+IPAddress(info, 30, 34).toString().substring(0, IPAddress(info, 30, 34).toString().length()-1));
		if(headerLength <= 20) {
			System.out.println("IP:\t No options\nIP:");
		}
		else {
			System.out.println("IP:\t More options\nIP:");
		}
		
		if(TCPFlag)
			TCPInfo(info,content);
		if(UDPFlag)
			UDPInfo(info);
		if(ICMPFlag)
			ICMPInfo(info);
	}
	
	
	public static void TCPInfo(int[] info, byte[] content) {
		System.out.println("TCP:\t ----- TCP Header -----");
		System.out.println("TCP:");
		long sourcePort = HexToDecimal(info, 34, 36);
		System.out.println("TCP:\t Source port = "+sourcePort);
		long destPort = HexToDecimal(info, 36, 38);
		System.out.println("TCP:\t Destination port = "+destPort);
		System.out.println("TCP:\t Sequence Number = "+HexToDecimal(info, 38, 42));
		long ack = HexToDecimal(info, 42, 46);
		System.out.println("TCP:\t Acknowledge Number = "+ack);
		int offset = Integer.parseInt(convertToMac(info, 46, 47).substring(0,1));
		System.out.println("TCP:\t Data offset = "+offset+ " bytes");
		System.out.println("TCP:\t Flags: 0x"+convertToMac(info, 47,48).toString().replace(":", ""));
		
		
		int hex=Integer.parseInt(convertToMac(info, 47, 48).toString(),16);
        StringBuilder result = new StringBuilder();

        for(int index = 15; index >= 0 ; index--) {
            int index1 = 1 << index;
            result.append((hex & index1) != 0 ? "1" : "0");
        }
        result.replace(result.length() - 1, result.length(), "");
        StringBuilder str = new StringBuilder();
        str=str.append(result).reverse();
        String[] flagVal={"Fin","Syn","Reset","Push","Acknowldgement","Urgent pointer"};
        for(int i=0;i<=5;i++){
            String rep="........";
            char[] arr=rep.toCharArray();
            if(str.charAt(i)=='0'){
                arr[7-i]='0';
                System.out.println("TCP:\t\t "+new String(arr)+"= No "+ flagVal[i]);
            }
            else{
                arr[7-i]='1';
                System.out.println("TCP:\t\t "+new String(arr)+"= "+ flagVal[i]);
            }
        }
		System.out.println("TCP:\t Window = " +HexToDecimal(info, 48, 50));
		String checksome = "0x"+convertToMac(info, 50, 52).toString().replace(":", "");
		System.out.println("TCP:\t Checksum = " +checksome);
		System.out.println("TCP:\t Urgent Pointer = "+HexToDecimal(info, 52, 54));
		int numberOfoptions =0;
		if(offset == 5)
			System.out.println("TCP:\t No options");
		else {
			System.out.println("TCP:\t More options");
			numberOfoptions = (offset - 5) * 4;
		}
		System.out.println("TCP:\t ");
		System.out.println("TCP:\t Data: (first 64 bytes):");
		int end = info.length-1;
		String data = convertToMac(info, numberOfoptions+57, ((end<121)? end:121)).toString().replace(":", "");
		String dataHex = printData(data);
		System.out.println("TCP:\t"+dataHex);
			
	}
	
	
	public static void UDPInfo(int[] info) {
		System.out.println("UDP:\t ----- UDP Header -----");
		System.out.println("UDP:");
		System.out.println("UDP:\t Source port =  " +HexToDecimal(info, 34, 36));
		System.out.println("UDP:\t Destination port =  " +HexToDecimal(info, 36, 38));
		System.out.println("UDP:\t Length =  " +HexToDecimal(info, 38, 40));
		String checksome = "0x"+convertToMac(info, 40, 42).toString().replace(":", "");
		System.out.println("UDP:\t Checksum =  " +checksome);
		System.out.println("UDP:\t Data: (first 64 bytes)");	//to do
		int end = info.length -1;
		String data = convertToMac(info, 42, ((end < 105)? end:105)).toString().replace(":", "");
		System.out.println("UDP:\t "+printData(data));
		
		
		
		
	}
	
	public static void ICMPInfo(int[] info)	{
		System.out.println("ICMP:\t ----- ICMP Header -----\nICMP:");
		long icmpType  = HexToDecimal(info, 34, 35);
		System.out.print("ICMP:\t Type: "+icmpType );
		if(icmpType == 8) {
			System.out.println("(Echo Request)");
		}
		else if (icmpType == 0)
			System.out.println("(Echo Reply)");
		else if (icmpType == 3) 
			System.out.println("Destination Unreachable");
		else if (icmpType == 11) 
			System.out.println("Time exceeded");
		else
			System.out.println("Other type");
		
		System.out.println("ICMP:\t Code = "+HexToDecimal(info, 35, 36));
		String checksome = "0x"+convertToMac(info, 36, 38).toString().replace(":", "");
		System.out.println("ICMP:\t Checksome = "+checksome);
		System.out.println("ICMP:");
		
	}
	
	
	
	
	
		public static void main(String[] args) 
		{
			File file = new File(args[0]);
			byte[] content = new byte[(int)file.length()];
			int[] Unsignedcontent = new int[(int)file.length()];
			try {
				content = Files.readAllBytes(Paths.get(args[0]));
			} catch (IOException e) {
				System.out.println("File not found");
				System.exit(0);
			}
			for(int index = 0; index < file.length(); index++ ) {
				Unsignedcontent[index] = Byte.toUnsignedInt(content[index]);
			}
			etherInfo(Unsignedcontent,content);
		}
	}


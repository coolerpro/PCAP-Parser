package org.example.pcapparser;

import io.pkts.PacketHandler;
import io.pkts.Pcap;
import io.pkts.buffer.Buffer;
import io.pkts.packet.PCapPacket;
import io.pkts.packet.Packet;
import io.pkts.packet.TCPPacket;
import io.pkts.packet.UDPPacket;
import io.pkts.protocol.Protocol;

import java.io.*;
import java.net.*;
import java.util.ArrayList;
import java.util.List;
import java.util.StringTokenizer;
import java.util.UUID;

import static java.lang.System.in;
import static java.lang.System.out;

public class Main {

    static int RTSPSeqNb = 0;
    static String RTSPid = UUID.randomUUID().toString();
    static int RTP_dest_port = 0;

    public final static int FILE_SIZE = 6022386; //Integer.MAX_VALUE;
    public final static String
            FILE_TO_RECEIVED = "file-rec.pcap";

    final static String CRLF = "\r\n";

    final static int INIT = 0;
    final static int READY = 1;
    final static int PLAYING = 2;
    //rtsp message types
    final static int SETUP = 3;
    final static int PLAY = 4;
    final static int PAUSE = 5;
    final static int TEARDOWN = 6;
    final static int DESCRIBE = 7;

    static BufferedReader RTSPBufferedReader;
    static BufferedWriter RTSPBufferedWriter;

    static String VideoFileName;


    public static void main(String[] args) throws IOException {


        try (ServerSocket server = new ServerSocket(554)) {
            out.println("Сервер запущен");

            try (Socket serverSocket = server.accept()) {


                while (true) {

                    RTSPBufferedReader = new BufferedReader(new InputStreamReader(serverSocket.getInputStream()));
                    RTSPBufferedWriter = new BufferedWriter(new OutputStreamWriter(serverSocket.getOutputStream()));

                    String word = RTSPBufferedReader.readLine();
                    out.println("------------------------------");
                    out.println(word);

                    StringTokenizer tokens = new StringTokenizer(word);
                    String requestTypeString = tokens.nextToken();

                    String SeqNumLine = RTSPBufferedReader.readLine();
                    out.println(SeqNumLine);
                    tokens = new StringTokenizer(SeqNumLine);
                    tokens.nextToken();
                    RTSPSeqNb = Integer.parseInt(tokens.nextToken());


                    if ((new String(requestTypeString)).compareTo("OPTIONS") == 0) {

                        StringWriter writer = new StringWriter();

                        writer.write("Server: UServer 0.9.7_rc1" + CRLF);
                        writer.write("Public: DESCRIBE, SETUP, TEARDOWN, PLAY, PAUSE, OPTIONS, ANNOUNCE, RECORD, GET_PARAMETER" + CRLF);
                        writer.write(CRLF);


                        sendResponse(writer.toString());

                    } else if ((new String(requestTypeString)).compareTo("DESCRIBE") == 0) {


                        StringWriter writer = new StringWriter();
                        StringWriter bodyWriter = new StringWriter();

                        bodyWriter.write("m=video 0 RTP/AVP 96" + CRLF);
                        bodyWriter.write("a=rtpmap:96 MP4V-ES/5544" + CRLF);
                        bodyWriter.write("a=control:trackID=0" + CRLF);

                        bodyWriter.write("m=audio 0 RTP/AVP 97" + CRLF);
                        bodyWriter.write("a=rtpmap:97 mpeg4-generic/32000/2" + CRLF);
                        bodyWriter.write("a=control:trackID=1" + CRLF);


                        String bodyStr = bodyWriter.toString();

                        writer.write("Content-Base: rtsp://127.0.0.1:554/" + CRLF);
                        writer.write("Content-Type: " + "application/sdp" + CRLF);
                        writer.write("Content-Length: " + bodyStr.length() + CRLF);

                        writer.write(CRLF);

                        writer.write(bodyStr);

                        sendResponse(writer.toString());


                    } else if ((new String(requestTypeString)).compareTo("SETUP") == 0) {


                        String nextLine = RTSPBufferedReader.readLine();
                        out.println(nextLine);
                        nextLine = RTSPBufferedReader.readLine();
                        out.println(nextLine);

                        tokens = new StringTokenizer(nextLine);
                        tokens.nextToken();
                        String tPorts = tokens.nextToken();
                        out.println(tPorts);

                        String port1 = null;
                        String port2 = null;
                        if (!tPorts.isEmpty()) {
                            String[] par = tPorts.split(";");
                            if (par.length > 2) {
                                String[] portsStr = par[2].split("=");
                                if (portsStr.length > 1) {
                                    String[] ports = portsStr[1].split("-");
                                    if (ports.length > 1) {
                                        port1 = ports[0];
                                        port2 = ports[1];
                                    }
                                }
                            }
                        }

                        StringWriter writer = new StringWriter();

                        writer.write("Transport: RTP/AVP;unicast;client_port=" + port1 + "-" + port2 + CRLF);

                        writer.write(CRLF);


                        sendResponse(writer.toString());

                    } else if ((new String(requestTypeString)).compareTo("PLAY") == 0) {

                        StringWriter writer = new StringWriter();

                        writer.write("Range: npt = 0.000-" + CRLF);
                        writer.write("RTP-Info: url=trackID=0;seq=1;rtptime=0,url=trackID=1;seq=1;rtptime=0" + CRLF);

                        writer.write(CRLF);

                        sendResponse(writer.toString());

                        File pcapFile = new File(FILE_TO_RECEIVED);

                        final Pcap pcap = Pcap.openStream(pcapFile);

                        pcap.loop(new PacketHandler() {
                            @Override
                            public boolean nextPacket(Packet packet) throws IOException {

                                if (packet.hasProtocol(Protocol.TCP)) {

                                    TCPPacket tcpPacket = (TCPPacket) packet.getPacket(Protocol.TCP);
                                    Buffer buffer = tcpPacket.getPayload();
                                    if (buffer != null) {
                                        System.out.println("TCP: " + buffer);
                                    }
                                } else if (packet.hasProtocol(Protocol.UDP)) {

                                    UDPPacket udpPacket = (UDPPacket) packet.getPacket(Protocol.UDP);
                                    Buffer buffer = udpPacket.getPayload();
                                    if (buffer != null) {
                                        System.out.println("UDP: " + buffer);
                                    }
                                }
                                return true;
                            }
                        });

                    }
                }
            } catch (IOException e) {
                e.printStackTrace();
                out.println(e);
            }
        } catch (IOException e) {
            e.printStackTrace();
            out.println(e);
        }
    }

    private static void sendResponse(String des) {
        try {
            RTSPBufferedWriter.write("RTSP/1.0 200 OK" + CRLF);
            RTSPBufferedWriter.write("CSeq: " + RTSPSeqNb + CRLF);
            RTSPBufferedWriter.write("Session: " + RTSPid + CRLF);

            RTSPBufferedWriter.write(des);

            RTSPBufferedWriter.flush();
            System.out.println("RTSP Server - Sent response to Client.");
        } catch (Exception ex) {
            System.out.println("Exception caught: " + ex);
            System.exit(0);
        }
    }

    private static void sendResponse() {
        try {
            RTSPBufferedWriter.write("RTSP/1.0 200 OK" + CRLF);
            RTSPBufferedWriter.write("CSeq: " + RTSPSeqNb + CRLF);
            RTSPBufferedWriter.write("Session: " + RTSPid + CRLF);


            RTSPBufferedWriter.flush();
            System.out.println("RTSP Server - Sent response to Client.");
        } catch (Exception ex) {
            System.out.println("Exception caught: " + ex);
            System.exit(0);
        }
    }


    //        final Pcap pcap = Pcap.openStream("rtsp://wowzaec2demo.streamlock.net/vod/mp4:BigBuckBunny_115k.mov");
//
//        pcap.loop(new PacketHandler() {
//            @Override
//            public boolean nextPacket(Packet packet) throws IOException {
//
//                if (packet.hasProtocol(Protocol.TCP)) {
//
//                    TCPPacket tcpPacket = (TCPPacket) packet.getPacket(Protocol.TCP);
//                    Buffer buffer = tcpPacket.getPayload();
//                    if (buffer != null) {
//                        System.out.println("TCP: " + buffer);
//                    }
//                } else if (packet.hasProtocol(Protocol.UDP)) {
//
//                    UDPPacket udpPacket = (UDPPacket) packet.getPacket(Protocol.UDP);
//                    Buffer buffer = udpPacket.getPayload();
//                    if (buffer != null) {
//                        System.out.println("UDP: " + buffer);
//                    }
//                }
//                return true;
//            }
//        });

//    private int parseRequest() {
//        int request_type = -1;
//        try {
//            //parse request line and extract the request_type:
//            String RequestLine = RTSPBufferedReader.readLine();
//            out.println("RTSP Server - Received from Client:");
//            out.println(RequestLine);
//
//            StringTokenizer tokens = new StringTokenizer(RequestLine);
//            String request_type_string = tokens.nextToken();
//
//            //convert to request_type structure:
//            if ((new String(request_type_string)).compareTo("SETUP") == 0)
//                request_type = SETUP;
//            else if ((new String(request_type_string)).compareTo("PLAY") == 0)
//                request_type = PLAY;
//            else if ((new String(request_type_string)).compareTo("PAUSE") == 0)
//                request_type = PAUSE;
//            else if ((new String(request_type_string)).compareTo("TEARDOWN") == 0)
//                request_type = TEARDOWN;
//            else if ((new String(request_type_string)).compareTo("DESCRIBE") == 0)
//                request_type = DESCRIBE;
//
//            if (request_type == SETUP) {
//                //extract VideoFileName from RequestLine
//                VideoFileName = tokens.nextToken();
//            }
//
//            //parse the SeqNumLine and extract CSeq field
//            String SeqNumLine = RTSPBufferedReader.readLine();
//            out.println(SeqNumLine);
//            tokens = new StringTokenizer(SeqNumLine);
//            tokens.nextToken();
//            RTSPSeqNb = Integer.parseInt(tokens.nextToken());
//
//            //get LastLine
//            String LastLine = RTSPBufferedReader.readLine();
//            out.println(LastLine);
//
//            tokens = new StringTokenizer(LastLine);
//            if (request_type == SETUP) {
//                //extract RTP_dest_port from LastLine
//                for (int i=0; i<3; i++)
//                    tokens.nextToken(); //skip unused stuff
//                RTP_dest_port = Integer.parseInt(tokens.nextToken());
//            }
//            else if (request_type == DESCRIBE) {
//                tokens.nextToken();
//                String describeDataType = tokens.nextToken();
//            }
//            else {
//                //otherwise LastLine will be the SessionId line
//                tokens.nextToken(); //skip Session:
//                RTSPid = tokens.nextToken();
//            }
//        } catch(Exception ex) {
//            out.println("Exception caught: "+ex);
//            System.exit(0);
//        }
//
//        return(request_type);
//    }
//
//    // Creates a DESCRIBE response string in SDP format for current media
//    private String describe() {
//        StringWriter writer1 = new StringWriter();
//        StringWriter writer2 = new StringWriter();
//
//        // Write the body first so we can get the size later
//        writer2.write("v=0" + CRLF);
//        writer2.write("m=video " + RTSP_dest_port + " RTP/AVP " + MJPEG_TYPE + CRLF);
//        writer2.write("a=control:streamid=" + RTSPid + CRLF);
//        writer2.write("a=mimetype:string;\"video/MJPEG\"" + CRLF);
//        String body = writer2.toString();
//
//        writer1.write("Content-Base: " + VideoFileName + CRLF);
//        writer1.write("Content-Type: " + "application/sdp" + CRLF);
//        writer1.write("Content-Length: " + body.length() + CRLF);
//        writer1.write(body);
//
//        return writer1.toString();
//    }
//
//    //------------------------------------
//    //Send RTSP Response
//    //------------------------------------
//    private void sendResponse() {
//        try {
//            RTSPBufferedWriter.write("RTSP/1.0 200 OK"+CRLF);
//            RTSPBufferedWriter.write("CSeq: "+RTSPSeqNb+CRLF);
//            RTSPBufferedWriter.write("Session: "+RTSPid+CRLF);
//            RTSPBufferedWriter.flush();
//            out.println("RTSP Server - Sent response to Client.");
//        } catch(Exception ex) {
//            out.println("Exception caught: "+ex);
//            System.exit(0);
//        }
//    }
//
//    private void sendDescribe() {
//        String des = describe();
//        try {
//            RTSPBufferedWriter.write("RTSP/1.0 200 OK");
//            RTSPBufferedWriter.write("CSeq: "+RTSPSeqNb+CRLF);
//            RTSPBufferedWriter.write(des);
//            RTSPBufferedWriter.flush();
//            out.println("RTSP Server - Sent response to Client.");
//        } catch(Exception ex) {
//            out.println("Exception caught: "+ex);
//            System.exit(0);
//        }
//    }


}

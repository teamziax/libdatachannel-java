package tel.schich.libdatachannel;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.*;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

/** Real UDP regression for imported identity, explicit ICE and deferred mux delivery. */
public final class NativeTransportProbe {
    static final InetAddress LOOPBACK=InetAddress.getLoopbackAddress();
    static final int PORT=49184;
    static String field(String sdp,String name) {
        return sdp.lines().filter(x->x.startsWith("a="+name+":")).findFirst().orElseThrow().substring(name.length()+3).trim();
    }
    record DeferredRequest(byte[] packet,String address,int port,long firstNanos) {}
    // Generic RFC 5389 short-term credential check. No application authorization is encoded.
    static DeferredRequest validate(byte[] packet,String address,int port,String expectedUser,String password) throws Exception {
        if(packet.length<20 || packet.length>2048) return null;
        ByteBuffer b=ByteBuffer.wrap(packet);
        if(b.getShort(0)!=1 || b.getInt(4)!=0x2112a442 || Short.toUnsignedInt(b.getShort(2))+20!=packet.length) return null;
        String username=null; int integrity=-1;
        for(int i=20;i<packet.length;) {
            if(i+4>packet.length) return null;
            int type=Short.toUnsignedInt(b.getShort(i)), len=Short.toUnsignedInt(b.getShort(i+2));
            if(i+4+len>packet.length) return null;
            if(type==6) { if(username!=null || integrity!=-1) return null; username=new String(packet,i+4,len,StandardCharsets.US_ASCII); }
            if(type==8) { if(integrity!=-1 || len!=20 || username==null) return null; integrity=i; }
            i+=4+((len+3)&~3); if(i>packet.length) return null;
        }
        if(!expectedUser.equals(username) || integrity<0) return null;
        byte[] signed=Arrays.copyOf(packet,integrity);
        ByteBuffer.wrap(signed).putShort(2,(short)(integrity+24-20));
        Mac mac=Mac.getInstance("HmacSHA1");
        mac.init(new SecretKeySpec(password.getBytes(StandardCharsets.US_ASCII),"HmacSHA1"));
        if(!MessageDigest.isEqual(mac.doFinal(signed),Arrays.copyOfRange(packet,integrity+4,integrity+24))) return null;
        return new DeferredRequest(packet,address,port,System.nanoTime());
    }
    static void check(boolean ok,String message) { if(!ok) throw new AssertionError(message); }
    public static void main(String[] args) throws Exception {
        Path certificate=Path.of(args[0]), key=Path.of(args[1]);
        byte[] der;
        try(var input=Files.newInputStream(certificate)) { der=CertificateFactory.getInstance("X.509").generateCertificate(input).getEncoded(); }
        String hostFingerprint=HexFormat.ofDelimiter(":").withUpperCase().formatHex(MessageDigest.getInstance("SHA-256").digest(der));
        try(PeerConnection encrypted=PeerConnection.createPeer(PeerConnectionConfiguration.DEFAULT.withDisableAutoNegotiation(true),
            Runnable::run,certificate,Path.of(args[2]),"test-only-password")) {
            encrypted.createDataChannel("encrypted-key");
            encrypted.setLocalDescription(null,"encryptedIdentity","publicTestPassword0000000");
            check(field(encrypted.localDescription(),"fingerprint").equals("sha-256 "+hostFingerprint),"encrypted key preserves certificate identity");
            check(encrypted.closeAndAwait(java.time.Duration.ofSeconds(5)),"encrypted-key peer cleanup");
        }
        System.out.println("native-transport PASS encryptedPemKey=true nullableDescriptionType=true");
        for(int ufragLength:new int[]{167,178,256}) run(certificate,key,hostFingerprint,ufragLength,false);
        run(certificate,key,hostFingerprint,167,true);
    }
    static void run(Path certificate,Path key,String hostFingerprint,int ufragLength,boolean wrongFingerprint) throws Exception {
        ArrayBlockingQueue<DeferredRequest> work=new ArrayBlockingQueue<>(4);
        String serverUfrag="s".repeat(ufragLength), serverPassword="fixedTestPassword0000000000000000";
        Set<String> approved=ConcurrentHashMap.newKeySet(), claimed=ConcurrentHashMap.newKeySet();
        AtomicInteger rejected=new AtomicInteger(),created=new AtomicInteger(),rawPackets=new AtomicInteger();
        AtomicReference<Throwable> failure=new AtomicReference<>();
        AtomicReference<byte[]> initialPacket=new AtomicReference<>();
        AtomicInteger initialPort=new AtomicInteger();
        List<PeerConnection> hosts=new ArrayList<>();
        CountDownLatch messages=new CountDownLatch(2), opened=new CountDownLatch(2);
        AtomicInteger channelMask=new AtomicInteger(), callbackCloseGuards=new AtomicInteger();
        CountDownLatch hostFailed=new CountDownLatch(1);
        try(RawUdpMuxListener mux=new RawUdpMuxListener(LOOPBACK,PORT,(packet,address,port)->{
            rawPackets.incrementAndGet(); String tuple=address+":"+port;
            if(approved.contains(tuple)) return true;
            try {
                DeferredRequest admission=validate(packet,address,port,serverUfrag+":clientFixtureUf",serverPassword);
                if(admission==null) {rejected.incrementAndGet();return false;}
                if(claimed.add(tuple)) {
                    initialPacket.set(packet); initialPort.set(port);
                    check(work.offer(admission),"bounded creation queue");
                }
            } catch(Exception error) {rejected.incrementAndGet();}
            return false;
        });PeerConnection client=PeerConnection.createPeer(PeerConnectionConfiguration.DEFAULT.withDisableAutoNegotiation(true).withBindAddress(LOOPBACK))) {
            long baselineNativeAttempts=PeerConnection.nativeCreationAttempts();
            check(mux.stats()[2]==0,"host has zero agents before any client packet");
            try(DatagramSocket invalid=new DatagramSocket()) {
                byte[] noise=new byte[40];invalid.send(new DatagramPacket(noise,noise.length,LOOPBACK,PORT));
                for(int i=0;i<100 && rejected.get()==0;i++) Thread.sleep(5);
                check(rejected.get()>0 && mux.stats()[2]==0 && mux.stats()[3]==0,"invalid datagram created no native state");
            }
            List<DataChannel> clientChannels=new ArrayList<>();
            for(int channel=0;channel<2;channel++) {
                String label=channel==0?"ordered":"unordered";
                var init=DataChannelInitSettings.DEFAULT.withReliability(new DataChannelReliability(channel==1,channel==1,0,0));
                var dc=client.createDataChannel(label,init);clientChannels.add(dc);
                dc.onOpen.register(d->{
                    try { client.closeAndAwait(java.time.Duration.ofMillis(1)); failure.set(new AssertionError("teardown wait must reject callback context")); }
                    catch(IllegalStateException expected) { callbackCloseGuards.incrementAndGet(); }
                    opened.countDown();ByteBuffer message=ByteBuffer.allocateDirect(2);message.put((byte)0).put((byte)(label.equals("ordered")?1:2)).flip();d.sendMessage(message);});
            }
            client.setLocalDescription("offer","clientFixtureUf","p".repeat(24));
            // Model generic signalling that advertises a provisioned endpoint identity.
            String answer="v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\na=group:BUNDLE 0\r\n"+
                "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\nc=IN IP4 0.0.0.0\r\na=mid:0\r\na=setup:active\r\n"+
                "a=ice-ufrag:"+serverUfrag+"\r\na=ice-pwd:"+serverPassword+"\r\na=fingerprint:sha-256 "+hostFingerprint+
                "\r\na=sctp-port:5000\r\na=max-message-size:262144\r\na=candidate:1 1 UDP 2130706431 127.0.0.1 "+PORT+" typ host\r\na=end-of-candidates\r\n";
            client.setRemoteDescription(answer,SessionDescriptionType.ANSWER);
            DeferredRequest admitted=work.poll(10,TimeUnit.SECONDS);check(admitted!=null,"raw STUN reaches listener before a peer exists");
            check(mux.stats()[2]==0 && PeerConnection.nativeCreationAttempts()==baselineNativeAttempts,"ingress validation precedes native peer construction");
            PeerConnection host=PeerConnection.createPeer(PeerConnectionConfiguration.DEFAULT.withDisableAutoNegotiation(true).withBindAddress(LOOPBACK)
                .withEnableIceUdpMux(true).withPortRangeBegin((short)PORT).withPortRangeEnd((short)PORT),Runnable::run,certificate,key);
            hosts.add(host);created.incrementAndGet();
            check(PeerConnection.nativeCreationAttempts()==baselineNativeAttempts+1,"exactly one native creation attempt");
            check(System.nanoTime()>admitted.firstNanos(),"monotonic validation before creation");
            host.onStateChange.register((p,state)->{if(state==PeerState.RTC_FAILED) hostFailed.countDown();});
            host.onDataChannel.register((p,dc)->{
                String label=dc.label();int bit=label.equals("ordered")?1:label.equals("unordered")?2:0;
                if(bit==0){failure.set(new AssertionError("unexpected label"));return;}
                channelMask.getAndUpdate(mask->mask|bit);
                dc.onMessage.register(DataChannelCallback.Message.handleBinary((d,buffer)->{
                    try {check(buffer.remaining()==2 && buffer.get()==0 && buffer.get()==bit,"channel identity and payload");messages.countDown();}
                    catch(Throwable error){failure.set(error);}
                }));
            });
            String remoteOffer=client.localDescription();
            if(wrongFingerprint) {
                String fingerprint=field(remoteOffer,"fingerprint");
                char replacement=fingerprint.charAt(8)=='0'?'1':'0';
                remoteOffer=remoteOffer.replace(fingerprint,fingerprint.substring(0,8)+replacement+fingerprint.substring(9));
            }
            host.setRemoteDescription(remoteOffer,SessionDescriptionType.OFFER);
            host.setLocalDescription("answer",serverUfrag,serverPassword);
            check(field(host.localDescription(),"fingerprint").equals("sha-256 "+hostFingerprint),"published native certificate identity");
            check(field(host.localDescription(),"ice-ufrag").equals(serverUfrag),"native preserved explicit ICE username");
            approved.add(admitted.address()+":"+admitted.port());
            mux.replay(initialPacket.getAndSet(null),LOOPBACK,initialPort.get());
            if(wrongFingerprint) {
                check(hostFailed.await(15,TimeUnit.SECONDS),"DTLS rejects an incorrect remote fingerprint");
                check(channelMask.get()==0 && opened.getCount()==2,"wrong certificate opens no channels");
                System.out.println("native-transport PASS wrongRemoteFingerprint=dtls-rejected channels=0");
                for(PeerConnection peer:hosts) check(peer.closeAndAwait(java.time.Duration.ofSeconds(5)),"native teardown completes before releasing capacity");hosts.clear();
                return;
            }
            check(opened.await(10,TimeUnit.SECONDS),"both client channels open");
            check(messages.await(10,TimeUnit.SECONDS),"both channels deliver distinct binary messages");
            check(failure.get()==null && callbackCloseGuards.get()==2,"native callbacks completed without failure and cannot wait on themselves");
            check(created.get()==1 && work.isEmpty() && channelMask.get()==3,"one lazy peer and both channels");
            long[] stats=mux.stats();check(stats[2]==1 && stats[3]==1,"one fixed-port agent and tuple");
            System.out.println("native-transport PASS ufragChars="+ufragLength+" hostPeers="+created.get()+" rawPackets="+rawPackets.get()+" channels=2");
            for(PeerConnection peer:hosts) check(peer.closeAndAwait(java.time.Duration.ofSeconds(5)),"native teardown completes before releasing capacity");hosts.clear();
        } finally {for(PeerConnection peer:hosts) check(peer.closeAndAwait(java.time.Duration.ofSeconds(5)),"native teardown completes before releasing capacity");}
    }
}

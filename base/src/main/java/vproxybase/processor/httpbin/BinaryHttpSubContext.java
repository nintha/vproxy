package vproxybase.processor.httpbin;

import vproxybase.processor.ExceptionWithoutStackTrace;
import vproxybase.processor.OOSubContext;
import vproxybase.processor.Processor;
import vproxybase.processor.httpbin.entity.Header;
import vproxybase.processor.httpbin.frame.*;
import vproxybase.processor.httpbin.hpack.HPack;
import vproxybase.util.ByteArray;
import vproxybase.util.LogType;
import vproxybase.util.Logger;
import vproxybase.util.RingBuffer;
import vproxybase.util.nio.ByteArrayChannel;

import java.util.*;
import java.util.function.Supplier;

public class BinaryHttpSubContext extends OOSubContext<BinaryHttpContext> {
    private static final ByteArray H2_PREFACE = ByteArray.from("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    private static final int H2_HEADER_SIZE = 3 + 1 + 1 + 4; // header length: len+type+flags+streamId
    private static final ByteArray SERVER_SETTINGS = SettingsFrame.newServerSettings().serializeH2(null).arrange();
    private static final ByteArray CLIENT_FIRST_FRAME =
        H2_PREFACE.concat(SettingsFrame.newClientSettings().serializeH2(null)).arrange();
    private static final ByteArray ACK_SETTINGS = SettingsFrame.newAck().serializeH2(null).arrange();

    // 0: initiated, expecting preface => 1
    // 1: expecting first settings frame header => 2
    // 2: expecting first settings frame => 3
    // 3: expecting frame header => 4|5|6
    // 4: expecting headers frame payload => 7|done
    // 5: expecting data frame payload => done
    // 6: expecting other frame payload => done (more handling if it's settings frame)
    // 7: expecting continuation frame header => 8
    // 8: expecting continuation frame => done
    public static final int STATE_PREFACE = 0;
    public static final int STATE_FIRST_SETTINGS_FRAME_HEADER = 1;
    public static final int STATE_FIRST_SETTINGS_FRAME = 2;
    public static final int STATE_FRAME_HEADER = 3;
    public static final int STATE_HEADERS_FRAME = 4;
    public static final int STATE_DATA_FRAME = 5;
    public static final int STATE_OTHER_FRAME = 6;
    public static final int STATE_CONTINUATION_FRAME_HEADER = 7;
    public static final int STATE_CONTINUATION_FRAME = 8;
    private int state = 0;

    private final HPack hpack = new HPack(SettingsFrame.DEFAULT_HEADER_TABLE_SIZE, SettingsFrame.DEFAULT_HEADER_TABLE_SIZE);

    final StreamHolder streamHolder;
    Stream lastPendingStream = null;

    private int connectionSendingWindow = SettingsFrame.DEFAULT_WINDOW_SIZE;
    private int connectionReceivingWindow = SettingsFrame.DEFAULT_WINDOW_SIZE;
    private int initialSendingWindow = connectionSendingWindow;
    private final int initialReceivingWindow = connectionReceivingWindow; // will not modify

    public BinaryHttpSubContext(BinaryHttpContext binaryHttpContext, int connId) {
        super(binaryHttpContext, connId);
        if (connId != 0) { // backend
            state = STATE_FIRST_SETTINGS_FRAME_HEADER;
        }
        streamHolder = new StreamHolder(this);
        init();
    }

    private void init() {
        if (state == STATE_FIRST_SETTINGS_FRAME_HEADER) {
            setLen(H2_HEADER_SIZE);
        } else {
            setLen(H2_PREFACE.length());
        }
    }

    @Override
    public Processor.Mode mode() {
        if (state == STATE_DATA_FRAME) {
            return Processor.Mode.proxy;
        }
        return Processor.Mode.handle;
    }

    private boolean expectNewFrame = true; // initially expect new frame

    @Override
    public boolean expectNewFrame() {
        return expectNewFrame;
    }

    private int len;

    @Override
    public int len() {
        return len;
    }

    private void setLen(int len) {
        this.len = len;
        if (parserMode) {
            this.chnl = ByteArrayChannel.fromEmpty(len);
        }
    }

    ByteArray dataToProxy;

    @Override
    public ByteArray feed(ByteArray data) throws Exception {
        switch (state) {
            case STATE_PREFACE:
                readPreface(data);
                break;
            case STATE_FIRST_SETTINGS_FRAME_HEADER:
            case STATE_FRAME_HEADER:
            case STATE_CONTINUATION_FRAME_HEADER:
                readFrameHeader(data);
                if (state == STATE_FIRST_SETTINGS_FRAME_HEADER) {
                    if (parsingFrame.type != HttpFrameType.SETTINGS)
                        throw new ExceptionWithoutStackTrace("expecting settings frame, but got " + parsingFrame.type);
                } else if (state == STATE_CONTINUATION_FRAME) {
                    if (parsingFrame.type != HttpFrameType.CONTINUATION)
                        throw new ExceptionWithoutStackTrace("expecting continuation frame, but got " + parsingFrame.type);
                }
                break;
            default:
                readFramePayload(data);
                break;
        }
        assert Logger.lowLevelDebug("binary http parser current frame: " + parsingFrame);
        var dataToProxy = this.dataToProxy;
        this.dataToProxy = null;
        return dataToProxy;
    }

    private void readPreface(ByteArray data) throws Exception {
        if (!data.equals(H2_PREFACE))
            throw new ExceptionWithoutStackTrace("not receiving preface: 0x" + data.toHexString());
        state = STATE_FIRST_SETTINGS_FRAME_HEADER;
        expectNewFrame = true;
        setLen(H2_HEADER_SIZE);
        parsingFrame = lastParsedFrame = new Preface();

        // preface is received, need send initial settings frame
        sendInitialFrame();
    }

    private void sendInitialFrame() {
        if (connId == 0) {
            // is server, need to send server settings
            produced = SERVER_SETTINGS;
        } else {
            // is client, need to send preface and settings
            produced = CLIENT_FIRST_FRAME;
        }
    }

    private static final Supplier<HttpFrame>[] h2frames;

    static {
        {
            Map<HttpFrame, Supplier<HttpFrame>> map = new HashMap<>();
            map.put(new ContinuationFrame(), ContinuationFrame::new);
            map.put(new DataFrame(), DataFrame::new);
            map.put(new GoAwayFrame(), GoAwayFrame::new);
            map.put(new HeadersFrame(), HeadersFrame::new);
            map.put(new PingFrame(), PingFrame::new);
            map.put(new PriorityFrame(), PriorityFrame::new);
            map.put(new PushPromiseFrame(), PushPromiseFrame::new);
            map.put(new RstStreamFrame(), RstStreamFrame::new);
            map.put(new SettingsFrame(), SettingsFrame::new);
            map.put(new WindowUpdateFrame(), WindowUpdateFrame::new);

            int max = 0;
            for (var f : map.keySet()) {
                if (f.type.h2type > max) {
                    max = f.type.h2type;
                }
            }
            //noinspection unchecked
            h2frames = new Supplier[max + 1];
            for (var en : map.entrySet()) {
                h2frames[en.getKey().type.h2type] = en.getValue();
            }
        }
    }

    private void readFrameHeader(ByteArray data) throws Exception {
        int len = data.uint24(0);
        byte type = data.get(3);
        byte flags = data.get(4);
        int streamId = data.int32(5);

        if (len > 16 * 1024 * 1024)
            throw new ExceptionWithoutStackTrace("frame too large, len: " + len);
        if (type < 0 || type >= h2frames.length || h2frames[type] == null)
            throw new ExceptionWithoutStackTrace("unknown h2 frame type: " + type);
        if (streamId < 0)
            throw new ExceptionWithoutStackTrace("invalid stream id: " + streamId);

        parsingFrame = h2frames[type].get();
        parsingFrame.length = len;
        parsingFrame.flags = flags;
        parsingFrame.streamId = streamId;
        parsingFrame.setFlags(flags);

        if (state == STATE_FIRST_SETTINGS_FRAME_HEADER) {
            if (parsingFrame.type != HttpFrameType.SETTINGS)
                throw new ExceptionWithoutStackTrace("expecting settings frame header but got " + parsingFrame.type);
        } else if (state == STATE_CONTINUATION_FRAME_HEADER) {
            if (parsingFrame.type != HttpFrameType.CONTINUATION)
                throw new ExceptionWithoutStackTrace("expecting headers frame header but got " + parsingFrame.type);
        }

        switch (parsingFrame.type) {
            case SETTINGS:
                if (state == STATE_FIRST_SETTINGS_FRAME_HEADER) {
                    state = STATE_FIRST_SETTINGS_FRAME;
                } else {
                    state = STATE_OTHER_FRAME;
                }
                break;
            case DATA:
                determineProxiedConnection();
                state = STATE_DATA_FRAME;
                break;
            case HEADERS:
                determineProxiedConnection();
                state = STATE_HEADERS_FRAME;
                break;
            case CONTINUATION:
                determineProxiedConnection();
                if (state != STATE_CONTINUATION_FRAME_HEADER) {
                    throw new ExceptionWithoutStackTrace("unexpected continuation frame");
                }
                state = STATE_CONTINUATION_FRAME;
                break;
            default:
                state = STATE_OTHER_FRAME;
                break;
        }

        if (parsingFrame.length == 0) {
            readFramePayload(ByteArray.allocate(0));
        } else {
            expectNewFrame = false; // expecting payload
            setLen(parsingFrame.length);
        }
    }

    private void determineProxiedConnection() {
        if (connId != 0) { // do not determine for backend connections
            return;
        }

        int streamId = parsingFrame.streamId;
        if (streamHolder.contains(streamId)) {
            Stream stream = streamHolder.get(streamId);
            assert Logger.lowLevelDebug("stream " + streamId + " already registered: " + stream);
            StreamSession session = stream.getSession();
            if (session == null) {
                assert Logger.lowLevelDebug("stream " + streamId + " session not set yet");
                ctx.currentProxyTarget = null;
            } else {
                ctx.currentProxyTarget = session.another(stream);
            }
        } else {
            assert Logger.lowLevelDebug("stream " + streamId + " not found, register it");
            streamHolder.register(streamId, initialSendingWindow, initialReceivingWindow);
            ctx.currentProxyTarget = null;
        }
    }

    private void readFramePayload(ByteArray data) throws Exception {
        parsingFrame.setPayload(this, data);

        handleFrame();

        if (parsingFrame.type == HttpFrameType.HEADERS
            && !((HeadersFrame) parsingFrame).endHeaders) {
            state = STATE_CONTINUATION_FRAME_HEADER;
        } else if (parsingFrame.type == HttpFrameType.CONTINUATION
            && !((ContinuationFrame) parsingFrame).endHeaders) {
            state = STATE_CONTINUATION_FRAME_HEADER;
        } else {
            state = STATE_FRAME_HEADER;
        }

        expectNewFrame = true;
        setLen(H2_HEADER_SIZE);
        lastParsedFrame = parsingFrame;
    }

    private void handleFrame() throws Exception {
        if (state == STATE_FIRST_SETTINGS_FRAME) {
            handleFirstSettingsFrame();
        } else if (parsingFrame instanceof HeadersFrame) {
            HeadersFrame headersFrame = (HeadersFrame) parsingFrame;
            handleAllHeaders();
            if (headersFrame.endHeaders) {
                handleEndHeaders();
            }
            serializeToProxy(parsingFrame);
        } else if (parsingFrame instanceof ContinuationFrame) {
            handleAllHeaders();
            ContinuationFrame continuationFrame = (ContinuationFrame) parsingFrame;
            if (continuationFrame.endHeaders) {
                handleEndHeaders();
            }
            serializeToProxy(parsingFrame);
        } else if (parsingFrame instanceof SettingsFrame) {
            handleSettingsFrame();
        } else if (parsingFrame instanceof WindowUpdateFrame) {
            handleWindowUpdate();
        }
    }

    private void serializeToProxy(HttpFrame frame) throws Exception {
        int streamId = frame.streamId;
        if (streamId == 0) {
            String err = "frames used to call serializeToProxy must be attached to a stream";
            Logger.error(LogType.IMPROPER_USE, err);
            throw new Exception(err);
        }
        Stream stream = streamHolder.get(streamId);
        if (stream == null) {
            String err = "cannot proxy frame " + frame + " because the stream is not registered";
            Logger.warn(LogType.INVALID_EXTERNAL_DATA, err);
            throw new Exception(err);
        }

        var session = stream.getSession();
        if (session == null) { // not established
            String err = "cannot proxy frame " + frame + " because the target stream is not established";
            Logger.warn(LogType.INVALID_EXTERNAL_DATA, err);
            throw new Exception(err);
        }

        var another = session.another(stream);
        frame.streamId = (int) another.streamId;
        dataToProxy = frame.serializeH2(another.ctx);
    }

    private void handleFirstSettingsFrame() throws ExceptionWithoutStackTrace {
        assert Logger.lowLevelDebug("got first settings frame:" + parsingFrame);
        SettingsFrame settings = (SettingsFrame) parsingFrame;
        if (settings.ack) {
            throw new ExceptionWithoutStackTrace("the first settings frame must not be an ack");
        }
        doHandleSettingsFrame(settings);
        // in addition to ordinary settings frame handling
        // more settings may be processed in the settings frame
        if (settings.initialWindowSizeSet) {
            connectionSendingWindow += settings.initialWindowSize - initialSendingWindow;
            assert Logger.lowLevelDebug("current sendingWindow = " + connectionSendingWindow);
        }
    }

    private void sendSettingsAck() {
        produced = ACK_SETTINGS;
    }

    private void handleAllHeaders() {
        String path = null;
        String host = null;

        var headers = ((WithHeaders) parsingFrame).headers();
        for (var ite = headers.iterator(); ite.hasNext(); ) {
            Header h = ite.next();
            if (h.keyStr.equalsIgnoreCase("x-forwarded-for")) {
                ite.remove();
            } else if (h.keyStr.equalsIgnoreCase("x-client-port")) {
                ite.remove();
            } else if (connId == 0) { // is frontend, need to dispatch request by path and host
                if (h.keyStr.equalsIgnoreCase(":path")) {
                    path = new String(h.value);
                } else if (h.keyStr.equalsIgnoreCase("host")) {
                    host = new String(h.value);
                }
            }
        }

        if (connId == 0) { // frontend
            assert Logger.lowLevelDebug("retrieved path = " + path);
            assert Logger.lowLevelDebug("retrieved host = " + host);

            Stream s = streamHolder.get(parsingFrame.streamId);
            if (s != null) {
                s.updatePathAndHost(path, host);
            }
        }
    }

    private void handleEndHeaders() {
        var headers = ((WithHeaders) parsingFrame).headers();

        // add x-forwarded-for and x-client-port
        headers.add(new Header("x-forwarded-for", ctx.clientAddress.getAddress().formatToIPString()));
        headers.add(new Header("x-client-port", ctx.clientAddress.getPort() + ""));

        if (connId == 0) { // is frontend
            Stream s = streamHolder.get(parsingFrame.streamId);
            if (s != null) {
                ctx.currentHint = s.generateHint();
            }
        }
    }

    private void handleSettingsFrame() {
        assert Logger.lowLevelDebug("got settings frame: " + parsingFrame);
        SettingsFrame settings = (SettingsFrame) parsingFrame;
        if (settings.ack) {
            assert Logger.lowLevelDebug("is settings ack, ignore");
            return;
        }
        doHandleSettingsFrame(settings);
    }

    private void doHandleSettingsFrame(SettingsFrame settings) {
        if (settings.headerTableSizeSet) {
            int tableSize = settings.headerTableSize;
            hpack.setEncoderMaxHeaderTableSize(tableSize);
        }
        if (settings.initialWindowSizeSet) {
            initialSendingWindow = settings.initialWindowSize;
        }
        // since the settings frame is received, we need to send back an ack
        sendSettingsAck();
    }

    private void handleWindowUpdate() {
        assert Logger.lowLevelDebug("got window update frame: " + parsingFrame);
        WindowUpdateFrame windowUpdate = (WindowUpdateFrame) parsingFrame;
        int incr = windowUpdate.windowSizeIncrement;
        if (windowUpdate.streamId == 0) {
            connectionSendingWindow += incr;
            assert Logger.lowLevelDebug("current sendingWindow = " + connectionSendingWindow);
        } else {
            Stream stream = streamHolder.get(windowUpdate.streamId);
            if (stream == null) {
                return; // no need to update
            }
            stream.sendingWindow += incr;
        }
    }

    private ByteArray produced;

    @Override
    public ByteArray produce() {
        ByteArray produced = this.produced;
        this.produced = null;
        return produced;
    }

    @Override
    public void proxyDone() {
        if (state == STATE_DATA_FRAME) {
            assert Logger.lowLevelDebug("data frame proxy done");
            DataFrame data = (DataFrame) parsingFrame;
            decreaseReceivingWindow(data.streamId, data.length);
            state = STATE_FRAME_HEADER;
            expectNewFrame = true;
            setLen(H2_HEADER_SIZE);
        } else {
            Logger.shouldNotHappen("not expecting proxyDone called in state " + state);
        }
    }

    private void decreaseReceivingWindow(int streamId, int length) {
        connectionReceivingWindow -= length;
        assert Logger.lowLevelDebug("current connection rcv wnd: " + connectionReceivingWindow);
        if (connectionReceivingWindow < initialReceivingWindow / 2) {
            sendWindowUpdate(null);
        }

        Stream stream = streamHolder.get(streamId);
        if (stream == null) {
            assert Logger.lowLevelDebug("stream " + streamId + " not found");
        } else {
            stream.receivingWindow -= length;
            assert Logger.lowLevelDebug("stream " + streamId + " rcv wnd: " + stream.receivingWindow);
            if (stream.receivingWindow < initialReceivingWindow / 2) {
                sendWindowUpdate(stream);
            }
        }
    }

    private void sendWindowUpdate(Stream stream) {
        assert Logger.lowLevelDebug("send window update called on " + (stream == null ? 0 : stream.streamId));
        WindowUpdateFrame windowUpdate = new WindowUpdateFrame();
        if (stream == null) {
            windowUpdate.streamId = 0;
            windowUpdate.windowSizeIncrement = initialReceivingWindow - connectionReceivingWindow;
            connectionReceivingWindow = initialReceivingWindow;
        } else {
            windowUpdate.streamId = (int) stream.streamId;
            windowUpdate.windowSizeIncrement = initialReceivingWindow - stream.receivingWindow;
            stream.receivingWindow = initialReceivingWindow;
        }
        produced = windowUpdate.serializeH2(this);
    }

    @Override
    public ByteArray connected() {
        sendInitialFrame();
        return produce();
    }

    // fields and methods for parserMode
    private boolean parserMode = false;
    private ByteArrayChannel chnl;
    private HttpFrame parsingFrame;
    private HttpFrame lastParsedFrame;

    public HPack getHPack() {
        return hpack;
    }

    public void setParserMode() {
        if ((connId == 0 && state != STATE_PREFACE) || (connId != 0 && state != STATE_FIRST_SETTINGS_FRAME_HEADER))
            throw new IllegalStateException("the method must be called when initialization");
        this.parserMode = true;
        init();
    }

    public boolean skipFirstSettingsFrame() {
        if (state == 0) {
            state = STATE_FRAME_HEADER;
            return true;
        }
        return false;
    }

    public int getState() {
        return state;
    }

    public boolean isIdle() {
        return parsingFrame == lastParsedFrame;
    }

    public HttpFrame getFrame() {
        return lastParsedFrame;
    }

    // only used in parserMode
    public ByteArray feed(RingBuffer inBuffer) throws Exception {
        inBuffer.writeTo(chnl);
        if (chnl.free() == 0) {
            // fully read
            return feed(chnl.getArray());
        }
        // need to remove the frame
        if (parsingFrame == lastParsedFrame) {
            parsingFrame = null; // the frame is not fully read yet
        }
        return null;
    }
}

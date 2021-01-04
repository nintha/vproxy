package vproxybase.processor.httpbin;

import vproxybase.processor.ExceptionWithoutStackTrace;
import vproxybase.processor.OOSubContext;
import vproxybase.processor.Processor;
import vproxybase.processor.httpbin.entity.Header;
import vproxybase.processor.httpbin.frame.*;
import vproxybase.processor.httpbin.hpack.HPack;
import vproxybase.util.ByteArray;
import vproxybase.util.Logger;
import vproxybase.util.RingBuffer;
import vproxybase.util.nio.ByteArrayChannel;

import java.util.*;
import java.util.function.Supplier;

public class BinaryHttpSubContext extends OOSubContext<BinaryHttpContext> {
    private Processor.Mode mode = Processor.Mode.handle; // initially handle
    private boolean expectNewFrame = true; // initially expect new frame
    private int len;
    private ByteArray produced;

    private final HPack hpack = new HPack(SettingsFrame.DEFAULT_HEADER_TABLE_SIZE, SettingsFrame.DEFAULT_HEADER_TABLE_SIZE);
    private int state = 0;
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
    public static final int STATE_DATE_FRAME = 5;
    public static final int STATE_OTHER_FRAME = 6;
    public static final int STATE_CONTINUATION_FRAME_HEADER = 7;
    public static final int STATE_CONTINUATION_FRAME = 8;

    private static final ByteArray H2_PREFACE = ByteArray.from("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    private static final int H2_HEADER_SIZE = 3 + 1 + 1 + 4; // header length: len+type+flags+streamId

    public BinaryHttpSubContext(BinaryHttpContext binaryHttpContext, int connId) {
        super(binaryHttpContext, connId);
        if (connId != 0) { // backend
            state = STATE_FIRST_SETTINGS_FRAME_HEADER;
        }
        init();
    }

    private void init() {
        if (state == STATE_FIRST_SETTINGS_FRAME_HEADER) {
            setLen(H2_HEADER_SIZE);
        } else {
            setLen(H2_PREFACE.length());
        }
    }

    public HPack getHPack() {
        return hpack;
    }

    @Override
    public Processor.Mode mode() {
        return mode;
    }

    @Override
    public boolean expectNewFrame() {
        return expectNewFrame;
    }

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

    private ByteArray proxiedBytesFromFeed;

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
        var proxiedBytesFromFeed = this.proxiedBytesFromFeed;
        this.proxiedBytesFromFeed = null;
        return proxiedBytesFromFeed;
    }

    private void readPreface(ByteArray data) throws Exception {
        if (!data.equals(H2_PREFACE))
            throw new ExceptionWithoutStackTrace("not receiving preface: 0x" + data.toHexString());
        state = STATE_FIRST_SETTINGS_FRAME_HEADER;
        expectNewFrame = true;
        setLen(H2_HEADER_SIZE);
        parsingFrame = lastParsedFrame = new Preface();
    }

    public static final Supplier<HttpFrame>[] h2frames;

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
                state = STATE_DATE_FRAME;
                mode = Processor.Mode.proxy; // simply proxy the bytes
                break;
            case HEADERS:
                state = STATE_HEADERS_FRAME;
                break;
            case CONTINUATION:
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
            if (((HeadersFrame) parsingFrame).endHeaders) {
                handleHeaders((HeadersFrame) parsingFrame, Collections.emptyList());
            } else {
                lastHeadersAndContinuation.add(parsingFrame);
            }
        } else if (parsingFrame instanceof ContinuationFrame) {
            if (((ContinuationFrame) parsingFrame).endHeaders) {
                HeadersFrame headersFrame = (HeadersFrame) lastHeadersAndContinuation.get(0);
                List<ContinuationFrame> continuationFrames = new ArrayList<>(lastHeadersAndContinuation.size() - 1);
                for (int i = 1; i < lastHeadersAndContinuation.size(); ++i) {
                    continuationFrames.add((ContinuationFrame) lastHeadersAndContinuation.get(i));
                }
                handleHeaders(headersFrame, continuationFrames);
            } else {
                lastHeadersAndContinuation.add(parsingFrame);
            }
        } else if (parsingFrame instanceof SettingsFrame) {
            handleSettingsFrame();
        } else if (parsingFrame instanceof WindowUpdateFrame) {
            handleWindowUpdate();
        }
    }

    private void handleFirstSettingsFrame() {
        assert Logger.lowLevelDebug("got first settings frame:" + parsingFrame);
        SettingsFrame settings = (SettingsFrame) parsingFrame;
        if (settings.headerTableSizeSet) {
            int tableSize = settings.headerTableSize;
            hpack.setEncoderMaxHeaderTableSize(tableSize);
        }
    }

    private void handleHeaders(HeadersFrame headersFrame, List<ContinuationFrame> continuationFrames) throws Exception {
        lastHeadersAndContinuation.clear();

        HttpFrame frame;
        List<Header> headers;
        if (continuationFrames.isEmpty()) {
            frame = headersFrame;
            headers = headersFrame.headers;
        } else {
            frame = continuationFrames.get(continuationFrames.size() - 1);
            headers = continuationFrames.get(continuationFrames.size() - 1).headers;
        }
        // TODO

        proxiedBytesFromFeed = frame.serializeH2Payload(this);
    }

    private void handleSettingsFrame() {
        // TODO
    }

    private void handleWindowUpdate() throws Exception {
        // TODO
    }

    @Override
    public ByteArray produce() {
        ByteArray produced = this.produced;
        this.produced = null;
        return produced;
    }

    @Override
    public void proxyDone() {
        if (state == STATE_DATE_FRAME) {
            state = STATE_FRAME_HEADER;
            expectNewFrame = true;
            setLen(H2_HEADER_SIZE);
            mode = Processor.Mode.handle;
        } else {
            assert Logger.lowLevelDebug("not expecting proxyDone called in state " + state);
        }
    }

    @Override
    public ByteArray connected() {
        return null; // TODO
    }

    // stores headers and continuations, will inspect or modify them
    private final List<HttpFrame> lastHeadersAndContinuation = new ArrayList<>(2);
    // fields and methods for parserMode
    private boolean parserMode = false;
    private ByteArrayChannel chnl;
    private HttpFrame parsingFrame;
    private HttpFrame lastParsedFrame;

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

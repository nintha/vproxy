package net.cassite.vproxy.processor.http2;

import net.cassite.vproxy.component.proxy.Processor;
import net.cassite.vproxy.processor.OOSubContext;
import net.cassite.vproxy.util.Logger;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

// the impl corresponds to rfc7540
/*
 * preface magic:
 * 0x505249202a20485454502f322e300d0a0d0a534d0d0a0d0a
 *
 *
 * frame: change the stream id if needed
 *  +-----------------------------------------------+
 *  |                 Length (24)                   |
 *  +---------------+---------------+---------------+
 *  |   Type (8)    |   Flags (8)   |
 *  +-+-------------+---------------+-------------------------------+
 *  |R|                 Stream Identifier (31)                      |
 *  +=+=============================================================+
 *  |                   Frame Payload (0...)                      ...
 *  +---------------------------------------------------------------+
 * HEADERS: remove priority
 *  +---------------+
 *  |Pad Length? (8)|
 *  +-+-------------+-----------------------------------------------+
 *  |E|                 Stream Dependency? (31)                     |
 *  +-+-------------+-----------------------------------------------+
 *  |  Weight? (8)  |
 *  +-+-------------+-----------------------------------------------+
 *  |                   Header Block Fragment (*)                 ...
 *  +---------------------------------------------------------------+
 *  |                           Padding (*)                       ...
 *  +---------------------------------------------------------------+
 * SETTINGS: proxy and record for the handshake, then simply ignore
 * --------- NOTE: SETTINGS_HEADER_TABLE_SIZE will be set to 0
 *  +-------------------------------+
 *  |       Identifier (16)         |
 *  +-------------------------------+-------------------------------+
 *  |                        Value (32)                             |
 *  +---------------------------------------------------------------+
 * PUSH_PROMISE: change stream id if it's to be initiated by backend
 *  +---------------+
 *  |Pad Length? (8)|
 *  +-+-------------+-----------------------------------------------+
 *  |R|                  Promised Stream ID (31)                    |
 *  +-+-----------------------------+-------------------------------+
 *  |                   Header Block Fragment (*)                 ...
 *  +---------------------------------------------------------------+
 *  |                           Padding (*)                       ...
 *  +---------------------------------------------------------------+
 *
 * DATA: proxy
 * PRIORITY: ignore
 * RST_STREAM: proxy
 * PING: proxy
 * GOAWAY: proxy
 * WINDOW_UPDATE: ignore
 * CONTINUATION: proxy
 *
 * the lib will remove all stream dependency and drop priority packets
 */

public class Http2SubContext extends OOSubContext<Http2Context> {
    private static final byte[] SEQ_PREFACE_MAGIC = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".getBytes();

    private static final int LEN_FRAME_HEAD = 9; // 72
    private static final int LEN_PADDING = 1; // 8
    private static final int LEN_E_STREAMDEPENDENCY_WEIGHT = 5; // 1 + 31 + 8
    private static final int LEN_R_PROMISED_STREAM_ID = 4; // 1 + 31
    private static final int LEN_SETTING = 6; // 2 + 4

    private static final byte VALUE_SETTINGS_HEADER_TABLE_SIZE = 0x1; // will be set to 0

    private Http2Frame frame;
    private Http2Frame lastFrame;
    // The frame field holds the current processing frame, when the frame head part comes, the frame object will generate
    // when the whole payload of the frame is processed, the frame field will be set to null
    // The lastFrame field holds the last frame, it's used to retrieve the streamId
    // some frame process (such as the settings frame) will consume all payload from the frame, and the frame field
    // will be set to null. In this case, the streamId could not be retrieved. So we store the lastFrame when needed,
    // and set this field to null after streamId is retrieved.

    private int state;
    /*
     * 0 -> frontend handshake -> 1
     * 1 -> (idle) reading stream and length -> 2/3/4/-1
     * 2 -> proxy -> 1
     * 3 -> (headers) remove stream dependency in headers -> 5
     * 4 -> settings: we should manipulate and record the first settings frame, so set to a special state -> 1
     * 5 -> (headers) the header part after stream dependency -> 1
     * 6 -> (push-promise) the first few bits of a push-promise frame -> 7
     * 7 -> (push-promise) proxy the bits after first few bits -> 1
     * -1 -> ignore the frame -> 1
     */

    private Map<Integer, Integer> streamIdBack2Front = new HashMap<>();

    public Http2SubContext(Http2Context ctx, int connId) {
        super(ctx, connId);

        if (connId == 0) {
            state = 0;
        } else {
            state = 1;
        }
    }

    @Override
    public Processor.Mode mode() {
        switch (state) {
            case 0:
            case 1:
            case 3:
            case 4:
            case 6:
            case -1:
                return Processor.Mode.handle;
            case 2:
            case 5:
            case 7:
                return Processor.Mode.proxy;
            default:
                throw new Error("should not reach here");
        }
    }

    @Override
    public int len() {
        switch (state) {
            case 0:
                return SEQ_PREFACE_MAGIC.length + LEN_FRAME_HEAD;
            case 1:
                return LEN_FRAME_HEAD;
            case 3:
                // only reach here if the priority flag is set (but it's already removed by the handle method)
                return (frame.padded ? LEN_PADDING : 0) + LEN_E_STREAMDEPENDENCY_WEIGHT;
            case 4:
                // we will add one setting in the processor
                return frame.length - LEN_SETTING;
            case 5:
                // only reach here if the priority flag is set (but it's already removed by the handle method)
                // the frame.length already subtracted the stream dependency weight
                // so only minus PADDING here would be ok
                return frame.length - (frame.padded ? LEN_PADDING : 0);
            case 6:
                return (frame.padded ? LEN_PADDING : 0) + LEN_R_PROMISED_STREAM_ID;
            case 7:
                return frame.length - (frame.padded ? LEN_PADDING : 0) - LEN_R_PROMISED_STREAM_ID;
            case -1:
            case 2:
                return frame.length; // the frame itself
            default:
                throw new Error("should not reach here");
        }
    }

    @Override
    public byte[] feed(byte[] data) throws Exception {
        switch (state) {
            case 0:
                assert data.length == SEQ_PREFACE_MAGIC.length + LEN_FRAME_HEAD;
                // check the preface
                byte[] prefacePart = new byte[SEQ_PREFACE_MAGIC.length];
                System.arraycopy(data, 0, prefacePart, 0, SEQ_PREFACE_MAGIC.length);
                if (0 != Arrays.compare(prefacePart, SEQ_PREFACE_MAGIC)) {
                    throw new Exception("the preface magic is wrong! " + new String(data));
                }
                byte[] framePart = new byte[LEN_FRAME_HEAD];
                System.arraycopy(data, SEQ_PREFACE_MAGIC.length, framePart, 0, LEN_FRAME_HEAD);
                parseFrame(framePart);
                // ignore the result from handleFrame.
                // the first frame is always settings frame and should set state to 4
                if (frame.type != Http2Frame.Type.SETTINGS) {
                    throw new Exception("invalid http2 protocol, no settings after preface. current frame is " + frame);
                }
                handleSettingsFramePart(framePart);
                // re-fill the original data array, the length of payload should be modified
                System.arraycopy(framePart, 0, data, SEQ_PREFACE_MAGIC.length, framePart.length);
                assert state == 4;
                return data;
            case 1:
                parseFrame(data);
                return handleFrame(data);
            case 3:
                state = 5; // set to proxy anything left in the header
                if (frame.padded) {
                    assert Logger.lowLevelDebug("the frame is padded, the padding length is " + data[0]);
                    return new byte[data[0]]; // only return the PADDING part
                } else {
                    assert Logger.lowLevelDebug("the frame is not padded, so ignore this part");
                    return null; // not padded, so return nothing
                }
            case 4:
                data = handleSettings(data);
                lastFrame = frame;
                frame = null;
                state = 1;
                return data;
            case 6:
                translatePromisedStreamId(data, frame.padded ? LEN_PADDING : 0);
                state = 7;
                return data;
            case -1:
                lastFrame = frame;
                frame = null;
                state = 1;
                return null; // ignore
            case 2:
            case 5:
            default:
                throw new Error("should not reach here");
        }
    }

    private void parseFrame(byte[] data) {
        Http2Frame frame = new Http2Frame();
        frame.length = 0x0fffffff & (data[0] << 16 | data[1] << 8 | data[2]);
        byte type = data[3];
        switch (type) {
            case 0x1:
                frame.type = Http2Frame.Type.HEADERS;
                break;
            case 0x4:
                frame.type = Http2Frame.Type.SETTINGS;
                break;
            case 0x5: // PUSH_PROMISE
                frame.type = Http2Frame.Type.PUSH_PROMISE;
                break;
            case 0x2: // PRIORITY
            case 0x8: // WINDOW_UPDATE
                frame.type = Http2Frame.Type.IGNORE;
                break;
            default:
                frame.type = Http2Frame.Type.PROXY;
                break;
        }
        byte flags = data[4];
        if (0 != (flags & 0x8)) frame.padded = true;
        if (0 != (flags & 0x20)) frame.priority = true;
        if (0 != (flags & 0x1)) frame.ack = true; // maybe it means "end stream", but we don't care
        frame.streamIdentifier = data[5] << 24 | data[6] << 16 | data[7] << 8 | data[8];

        this.frame = frame;
        assert Logger.lowLevelDebug("get http2 frame: " + frame + " in connection = " + connId);
    }

    private byte[] handleFrame(byte[] frameBytes) throws Exception {
        // check (and modify) the stream id
        // if it's from frontend, we should try to record it first before modifying
        if (connId == 0) {
            ctx.tryRecordStream(this);
        }
        // translate the streamIdentifier
        if (frame.streamIdentifier != 0 && frame.streamIdentifier % 2 == 0) {
            // not 0 and is even
            // so it's started by a backend
            assert Logger.lowLevelDebug("modify streamIdentifier of the frame. " +
                "streamId=" + frame.streamIdentifier + ", connId=" + connId);

            Integer translatedStreamId;
            if (connId == 0) {
                translatedStreamId = ctx.streamIdFront2Back.get(frame.streamIdentifier);
            } else {
                translatedStreamId = this.streamIdBack2Front.get(frame.streamIdentifier);
            }
            if (translatedStreamId == null) {
                assert Logger.lowLevelDebug("the translatedStreamId is null, which is invalid." +
                    "The HTTP/2 protocol does not allow a server start new streams before push-promise, " +
                    "and the streamId should already been recorded when parsing the push-promise frame. " +
                    "But we allow this condition for possible 'HTTP/2-like' protocols.");
                if (connId != 0) {
                    // this will only happen when data is coming from backend
                    // otherwise, it's invalid
                    throw new Exception("cannot get translated stream id for " + frame.streamIdentifier);
                }
                translatedStreamId = ctx.nextServerStreamId();
                recordStreamMapping(translatedStreamId, frame.streamIdentifier);
            }

            assert Logger.lowLevelDebug("the translatedStreamId is " + translatedStreamId);
            if (!translatedStreamId.equals(frame.streamIdentifier)) {
                utilModifyStreamId(frameBytes, 5, translatedStreamId);
                frame.streamIdentifier = translatedStreamId;
            }
        }
        // we try to record the stream for backend after translated the streamId
        if (connId != 0) {
            ctx.tryRecordStream(this);
        }

        if (frame.type == Http2Frame.Type.HEADERS && frame.priority) {
            assert Logger.lowLevelDebug("got HEADERS frame with priority, we should remove the priority");
            state = 3;
            {
                // reset the length
                int forwardLen = frame.length - LEN_E_STREAMDEPENDENCY_WEIGHT;
                assert Logger.lowLevelDebug("the old length was " + frame.length + " new length is " + forwardLen);
                byte b0 = (byte) ((forwardLen >> 16) & 0xff);
                byte b1 = (byte) ((forwardLen >> 8) & 0xff);
                byte b2 = (byte) ((forwardLen) & 0xff);
                frameBytes[0] = b0;
                frameBytes[1] = b1;
                frameBytes[2] = b2;
                frame.length = forwardLen;
            }
            {
                // unset the priority bit
                frameBytes[4] = (byte) (frameBytes[4] & 0b1101_1111);
                frame.priority = false;
            }
            return frameBytes;
        } else if (frame.type == Http2Frame.Type.SETTINGS) {
            return handleSettingsFramePart(frameBytes);
        } else if (frame.type == Http2Frame.Type.PUSH_PROMISE) {
            state = 6;
            return frameBytes;
        } else if (frame.type == Http2Frame.Type.IGNORE) {
            assert Logger.lowLevelDebug("got an ignored frame of length " + frame.length);
            state = -1;
            return null;
        } else {
            state = 2; // default: do proxy
            return frameBytes;
        }
    }

    private byte[] handleSettingsFramePart(byte[] frameBytes) {
        if (connId == 0) {
            // frontend
            if (ctx.frontendHandshaking) {
                // we should manipulate and record the settings frame, so set to a special state
                state = 4;
                // add the length of a setting because we will add one in the processor
                {
                    frame.length += LEN_SETTING;
                    utilModifyFrameLength(frameBytes, frame.length);
                    assert Logger.lowLevelDebug("add LEN_SETTING to the frame coming from frontend, " +
                        "now the frame is " + frame);
                }
                ctx.settingsFrameHeader = frameBytes;
                ctx.frontendHandshaking = false; // the frontend handshaking is considered done
                return frameBytes;
            } else if (frame.ack) { // if it's a setting frame from frontend and is ack, proxy it
                state = 2; // proxy
                return frameBytes;
            }
        } else {
            // backend
            if (ctx.backendHandshaking) {
                if (frame.ack) { // get SETTINGS frame with ack set for the first time, means that the backend handshake is done
                    state = 2; // proxy the settings
                    ctx.backendHandshaking = false; // handshake done
                } else {
                    // add the length of a setting because we will add one in the processor
                    frame.length += LEN_SETTING;
                    utilModifyFrameLength(frameBytes, frame.length);
                    assert Logger.lowLevelDebug("add LEN_SETTING to the frame coming from backend, " +
                        "now the frame is " + frame);
                    // we should manipulate and record the settings frame, so set to a special state
                    state = 4;
                }
                return frameBytes;
            }
        }
        { // otherwise should ignore the frame, both for frontend and backend
            assert Logger.lowLevelDebug("dropping the SETTINGS frame " +
                "because it's not handshaking and not ack of the frontend connection");
            state = -1;
            return null;
        }
    }

    // concat a setting SETTINGS_HEADER_TABLE_SIZE = 0 to the frame, or change the value if it already exists
    private byte[] handleSettings(byte[] payload) {
        // make a bigger payload
        {
            byte[] foo = new byte[payload.length + LEN_SETTING];
            System.arraycopy(payload, 0, foo, 0, payload.length);
            payload = foo;
        }
        // try to find the SETTINGS_HEADER_TABLE_SIZE and change the value
        {
            int offsetOfSetting = payload.length - LEN_SETTING; // default: use the added part when not provided
            for (int i = 0; i < payload.length; i += LEN_SETTING) {
                // the identifier takes 2 bytes
                if (payload[i] == 0 && payload[i + 1] == VALUE_SETTINGS_HEADER_TABLE_SIZE) {
                    offsetOfSetting = i;
                    assert Logger.lowLevelDebug("found setting for the HEADER_TABLE_SIZE");
                    break;
                }
            }
            assert Logger.lowLevelDebug("writing HEADER_TABLE_SIZE at offset " + offsetOfSetting);
            // the identifier part
            payload[offsetOfSetting] = 0;
            payload[offsetOfSetting + 1] = VALUE_SETTINGS_HEADER_TABLE_SIZE;
            // the value part
            payload[offsetOfSetting + 2] = 0;
            payload[offsetOfSetting + 3] = 0;
            payload[offsetOfSetting + 4] = 0;
            payload[offsetOfSetting + 5] = 0;
        }

        // record the handshake if it's client connection
        if (connId == 0) {
            byte[] head = ctx.settingsFrameHeader;
            byte[] handshake = new byte[SEQ_PREFACE_MAGIC.length + head.length + payload.length];
            System.arraycopy(SEQ_PREFACE_MAGIC, 0, handshake, 0, SEQ_PREFACE_MAGIC.length);
            System.arraycopy(head, 0, handshake, SEQ_PREFACE_MAGIC.length, head.length);
            System.arraycopy(payload, 0, handshake, SEQ_PREFACE_MAGIC.length + head.length, payload.length);

            ctx.settingsFrameHeader = null;
            ctx.clientHandshake = handshake;
        }

        return payload;
    }

    private void translatePromisedStreamId(byte[] data, int offset) {
        Integer promisedStreamId = data[offset] << 24 | data[offset + 1] << 16 | data[offset + 2] << 8 | data[offset + 3];
        Integer translatedStreamId = ctx.nextServerStreamId();
        assert Logger.lowLevelDebug("push-promise frame > promised stream id is " + promisedStreamId +
            " translated stream id is " + translatedStreamId);
        recordStreamMapping(translatedStreamId, promisedStreamId);
        if (!promisedStreamId.equals(translatedStreamId)) {
            utilModifyStreamId(data, offset, translatedStreamId);
        }
    }

    private static void utilModifyStreamId(byte[] data, int offset, int streamId) {
        data[offset] = (byte) ((streamId >> 24) & 0xff);
        data[offset + 1] = (byte) ((streamId >> 16) & 0xff);
        data[offset + 2] = (byte) ((streamId >> 8) & 0xff);
        data[offset + 3] = (byte) ((streamId) & 0xff);
    }

    private static void utilModifyFrameLength(byte[] data, int length) {
        data[0] = (byte) ((length >> 16) & 0xff);
        data[1] = (byte) ((length >> 8) & 0xff);
        data[2] = (byte) ((length) & 0xff);
    }

    Integer currentStreamId() {
        assert frame != null || lastFrame != null;
        if (frame != null) {
            return frame.streamIdentifier;
        }
        Http2Frame f = lastFrame;
        lastFrame = null;
        return f.streamIdentifier;
    }

    void recordStreamMapping(Integer front, Integer back) {
        this.streamIdBack2Front.put(back, front);
        ctx.streamIdFront2Back.put(front, back);
    }

    @Override
    public void proxyDone() {
        // all proxy states goes to state 1
        // so simply set the frame to null and state 1 here
        state = 1;
        frame = null;
    }

    @Override
    public byte[] connected() {
        if (connId == 0) {
            return null;
        }
        return ctx.clientHandshake;
    }
}
package vproxybase.processor.httpbin;

import vproxybase.util.Logger;

public class StreamSession {
    public final Stream active;
    public final Stream passive;

    public StreamSession(Stream active, Stream passive) {
        this.active = active;
        this.passive = passive;
    }

    public Stream another(Stream stream) {
        if (stream == active) {
            return passive;
        }
        if (stream == passive) {
            return active;
        }
        String err = "stream " + stream + " is neither active nor passive";
        Logger.shouldNotHappen(err);
        throw new RuntimeException(err);
    }

    @Override
    public String toString() {
        return "StreamSession{" +
            "active=" + active +
            ", passive=" + passive +
            '}';
    }
}

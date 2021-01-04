package vproxybase.processor.httpbin;

import vproxybase.processor.Hint;
import vproxybase.processor.OOContext;

public class BinaryHttpContext extends OOContext<BinaryHttpSubContext> {
    // TODO
    @Override
    public int connection(BinaryHttpSubContext front) {
        return 0;
    }

    @Override
    public Hint connectionHint(BinaryHttpSubContext front) {
        return null;
    }

    @Override
    public void chosen(BinaryHttpSubContext front, BinaryHttpSubContext subCtx) {
        // TODO
    }
}

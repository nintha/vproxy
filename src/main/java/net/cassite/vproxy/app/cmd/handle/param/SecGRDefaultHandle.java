package net.cassite.vproxy.app.cmd.handle.param;

import net.cassite.vproxy.app.cmd.Command;
import net.cassite.vproxy.app.cmd.Param;

public class SecGRDefaultHandle {
    private SecGRDefaultHandle() {
    }

    public static void check(Command cmd) throws Exception {
        try {
            get(cmd);
        } catch (Exception e) {
            throw new Exception("invalid format for " + Param.secgrdefault.fullname);
        }
    }

    public static boolean get(Command cmd) {
        String dft = cmd.args.get(Param.secgrdefault);
        if (dft.equals("allow"))
            return true;
        if (dft.equals("deny"))
            return false;
        throw new IllegalArgumentException();
    }
}

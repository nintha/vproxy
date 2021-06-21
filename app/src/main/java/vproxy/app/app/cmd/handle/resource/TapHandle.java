package vproxy.app.app.cmd.handle.resource;

import vproxy.app.app.Application;
import vproxy.app.app.cmd.Command;
import vproxy.app.app.cmd.Param;
import vproxy.app.app.cmd.Resource;
import vproxy.app.app.cmd.ResourceType;
import vproxy.app.app.cmd.handle.param.AnnotationsHandle;
import vproxy.app.app.cmd.handle.param.FloodHandle;
import vproxy.app.app.cmd.handle.param.MTUHandle;
import vproxy.base.util.Annotations;
import vproxy.base.util.Utils;
import vproxy.base.util.exception.XException;
import vproxy.vswitch.Switch;

public class TapHandle {
    private TapHandle() {
    }

    public static void checkTapParent(Resource parent) throws Exception {
        if (parent == null)
            throw new Exception("cannot find " + ResourceType.tap.fullname + " on top level");
        if (parent.type != ResourceType.sw)
            throw new Exception(parent.type.fullname + " does not contain " + ResourceType.tap.fullname);
        SwitchHandle.checkSwitch(parent);
    }

    public static void checkCreateTap(Command cmd) throws Exception {
        String devPattern = cmd.resource.alias;
        if (devPattern.length() > 15) {
            throw new XException("tap dev name pattern too long: should <= 15");
        }
        String vni = cmd.args.get(Param.vni);
        if (vni == null) {
            throw new Exception("missing " + Param.vni.fullname);
        }
        if (!Utils.isInteger(vni)) {
            throw new Exception("invalid " + Param.vni.fullname + ", not an integer");
        }
        if (cmd.args.containsKey(Param.mtu)) {
            MTUHandle.check(cmd);
        }
        if (cmd.args.containsKey(Param.flood)) {
            FloodHandle.check(cmd);
        }
    }

    public static String add(Command cmd) throws Exception {
        String devPattern = cmd.resource.alias;
        int vni = Integer.parseInt(cmd.args.get(Param.vni));
        String postScript = cmd.args.get(Param.postscript);
        Switch sw = Application.get().switchHolder.get(cmd.prepositionResource.alias);
        Annotations anno = null;
        if (cmd.args.containsKey(Param.anno)) {
            anno = AnnotationsHandle.get(cmd);
        }
        Integer mtu = null;
        if (cmd.args.containsKey(Param.mtu)) {
            mtu = MTUHandle.get(cmd);
        }
        Boolean flood = null;
        if (cmd.args.containsKey(Param.flood)) {
            flood = FloodHandle.get(cmd);
        }
        var tap = sw.addTap(devPattern, vni, postScript, anno, mtu, flood);
        return tap.getTap().getTap().dev;
    }

    public static void forceRemove(Command cmd) throws Exception {
        String devPattern = cmd.resource.alias;
        Switch sw = Application.get().switchHolder.get(cmd.prepositionResource.alias);
        sw.delTap(devPattern);
    }
}

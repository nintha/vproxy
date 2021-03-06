package vproxyapp.app.cmd;

import vfd.IPPort;
import vfd.UDSPath;
import vproxyapp.app.Application;
import vproxyapp.app.DockerNetworkPluginControllerHolder;
import vproxyapp.app.HttpControllerHolder;
import vproxyapp.app.RESPControllerHolder;
import vproxyapp.app.cmd.handle.param.AddrHandle;
import vproxyapp.controller.DockerNetworkPluginController;
import vproxyapp.controller.HttpController;
import vproxyapp.controller.RESPController;
import vproxyapp.controller.StdIOController;
import vproxyapp.process.Shutdown;
import vproxybase.util.Callback;
import vproxybase.util.Logger;
import vproxybase.util.Utils;
import vproxybase.util.exception.AlreadyExistException;
import vproxybase.util.exception.NotFoundException;
import vproxybase.util.exception.XException;

import java.io.IOException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

public class SystemCommand {
    private SystemCommand() {
    }

    static final String systemCallHelpStr = "" +
        "\n        System call: help                          show this message" +
        "\n        System call: shutdown                      shutdown the vproxy process" +
        "\n        System call: load ${filepath}              load config commands from a file" +
        "\n        System call: save ${filepath}              save current config into a file" +
        "\n        System call: add resp-controller           start resp controller" +
        "\n                               ${alias}" +
        "\n                               address  ${bind addr}" +
        "\n                               password ${password}" +
        "\n        System call: remove resp-controller        stop resp controller" +
        "\n                               ${alias}" +
        "\n        System call: list-detail resp-controller   check resp controller" +
        "\n        System call: add http-controller           start http controller" +
        "\n                               ${alias}" +
        "\n                               address ${bind addr}" +
        "\n        System call: remove http-controller        stop http controller" +
        "\n                               ${alias}" +
        "\n        System call: list-detail http-controller   check http controller" +
        "\n        System call: add docker-network-plugin-controller         start docker net plugin ctl" +
        "\n                               ${alias}" +
        "\n                               path ${unix domain socket path}" +
        "\n        System call: remove docker-network-plugin-controller      stop docker net plugin ctl" +
        "\n                               ${alias}" +
        "\n        System call: list-detail docker-network-plugin-controller show docker net plugin ctl list" +
        "\n        System call: list config                   show current config";

    public static boolean allowNonStdIOController = false;

    public static boolean isSystemCall(String line) {
        return line.startsWith("System call:");
    }

    public static void handleSystemCall(String line, Callback<CmdResult, ? super Throwable> cb) {
        String from = Utils.stackTraceStartingFromThisMethodInclusive()[1].getClassName();
        String cmd = line.substring("System call:".length()).trim();
        outswitch:
        switch (cmd) {
            case "help":
                String helpStr = Command.helpString();
                List<String> helpStrLines = Arrays.asList(helpStr.split("\n"));
                cb.succeeded(new CmdResult(helpStr, helpStrLines, helpStr));
                break;
            case "shutdown":
                if (!from.equals(StdIOController.class.getName())) {
                    cb.failed(new XException("you can only call shutdown via StdIOController"));
                    break;
                }
                Shutdown.shutdown();
                cb.succeeded(new CmdResult());
                break;
            default:
                if (cmd.startsWith("load ")) {
                    if (!from.equals(StdIOController.class.getName())) {
                        cb.failed(new XException("you can only call load via StdIOController"));
                        break;
                    }
                    String[] split = cmd.split(" ");
                    if (split.length <= 1) {
                        cb.failed(new Exception("invalid system call for `load`: should specify a file name to load"));
                        break;
                    }
                    StringBuilder filename = new StringBuilder();
                    for (int i = 1; i < split.length; ++i) {
                        if (i != 1) {
                            filename.append(" ");
                        }
                        filename.append(split[i]);
                    }
                    try {
                        Shutdown.load(filename.toString(), new Callback<>() {
                            @Override
                            protected void onSucceeded(String value) {
                                cb.succeeded(new CmdResult());
                            }

                            @Override
                            protected void onFailed(Throwable err) {
                                cb.failed(err);
                            }
                        });
                    } catch (Exception e) {
                        cb.failed(new Exception("got exception when do pre-loading: " + Utils.formatErr(e)));
                    }
                    break;
                } else if (cmd.startsWith("save ")) {
                    if (!from.equals(StdIOController.class.getName())) {
                        cb.failed(new XException("you can only call save via StdIOController"));
                        break;
                    }
                    String[] split = cmd.split(" ");
                    if (split.length <= 1) {
                        cb.failed(new Exception("invalid system call for `save`: should specify a file name to save"));
                        break;
                    }
                    StringBuilder filename = new StringBuilder();
                    for (int i = 1; i < split.length; ++i) {
                        if (i != 1) {
                            filename.append(" ");
                        }
                        filename.append(split[i]);
                    }
                    try {
                        Shutdown.save(filename.toString());
                    } catch (Exception e) {
                        cb.failed(new Exception("got exception when saving: " + Utils.formatErr(e)));
                    }
                    cb.succeeded(new CmdResult());
                    break;
                } else if (cmd.startsWith("add ")) {
                    String[] arr = cmd.split(" ");
                    if (arr.length < 2) {
                        cb.failed(new Exception("invalid add command"));
                        break;
                    }
                    switch (arr[1]) {
                        case "resp-controller":
                            if (arr.length == 7) {
                                handleAddController("resp", arr, cb);
                                break outswitch;
                            }
                            break;
                        case "http-controller":
                            if (arr.length == 5) {
                                handleAddController("http", arr, cb);
                                break outswitch;
                            }
                            break;
                        case "docker-network-plugin-controller":
                            if (arr.length == 5) {
                                handleAddController("docker-network-plugin", arr, cb);
                                break outswitch;
                            }
                            break;
                    }
                } else if (cmd.startsWith("remove ")) {
                    String[] arr = cmd.split(" ");
                    if (arr.length < 2) {
                        cb.failed(new Exception("invalid remove command"));
                        break;
                    }
                    switch (arr[1]) {
                        case "resp-controller":
                            if (arr.length == 3) {
                                handleRemoveRespController(arr, cb);
                                break outswitch;
                            }
                            break;
                        case "http-controller":
                            if (arr.length == 3) {
                                handleRemoveHttpController(arr, cb);
                                break outswitch;
                            }
                            break;
                        case "docker-network-plugin-controller":
                            if (arr.length == 3) {
                                handleRemoveDockerNetworkPluginController(arr, cb);
                                break outswitch;
                            }
                            break;
                    }
                } else if (cmd.startsWith("list ")) {
                    String[] arr = cmd.split(" ");
                    if (arr.length < 2) {
                        cb.failed(new Exception("invalid list command"));
                        break;
                    }
                    switch (arr[1]) {
                        case "resp-controller":
                            if (arr.length == 2) {
                                handleListController("resp", false, cb);
                                break outswitch;
                            }
                            break;
                        case "http-controller":
                            if (arr.length == 2) {
                                handleListController("http", false, cb);
                                break outswitch;
                            }
                            break;
                        case "docker-network-plugin-controller":
                            if (arr.length == 2) {
                                handleListController("docker-network-plugin", false, cb);
                                break outswitch;
                            }
                            break;
                        case "config":
                            if (arr.length == 2) {
                                handleListConfig(cb);
                                break outswitch;
                            }
                            break;
                    }
                } else if (cmd.startsWith("list-detail ")) {
                    String[] arr = cmd.split(" ");
                    if (arr.length < 2) {
                        cb.failed(new Exception("invalid list-detail command"));
                        break;
                    }
                    switch (arr[1]) {
                        case "resp-controller":
                            if (arr.length == 2) {
                                handleListController("resp", true, cb);
                                break outswitch;
                            }
                            break;
                        case "docker-network-plugin-controller":
                            if (arr.length == 2) {
                                handleListController("docker-network-plugin", true, cb);
                                break outswitch;
                            }
                            break;
                        case "http-controller":
                            if (arr.length == 2) {
                                handleListController("http", true, cb);
                                break outswitch;
                            }
                            break;
                    }
                }
                cb.failed(new Exception("unknown or invalid system call `" + cmd + "`"));
        }
    }

    private static void handleListConfig(Callback<CmdResult, ? super XException> cb) {
        String config = Shutdown.currentConfig();
        List<String> lines = Arrays.asList(config.split("\n"));
        cb.succeeded(new CmdResult(config, lines, config));
    }

    private static void handleAddController(String type, String[] arr, Callback<CmdResult, ? super Throwable> cb) {
        Command cmd;
        try {
            cmd = Command.statm(Arrays.asList(arr));
        } catch (Exception e) {
            cb.failed(new Exception("invalid system call: " + Utils.formatErr(e)));
            return;
        }
        if (type.equals("docker-network-plugin")) {
            if (!cmd.args.containsKey(Param.path)) {
                cb.failed(new Exception("missing path"));
                return;
            }
        } else {
            if (!cmd.args.containsKey(Param.addr)) {
                cb.failed(new Exception("missing address"));
                return;
            }
        }
        if (type.equals("resp")) {
            // resp-controller needs password
            if (!cmd.args.containsKey(Param.pass)) {
                cb.failed(new Exception("missing password"));
                return;
            }
        }
        if (!type.equals("docker-network-plugin")) {
            try {
                AddrHandle.check(cmd);
            } catch (Exception e) {
                cb.failed(new XException("invalid system call, address is invalid: " + Utils.formatErr(e)));
                return;
            }
        }

        IPPort addr;
        if (type.equals("docker-network-plugin")) {
            addr = new UDSPath(cmd.args.get(Param.path));
        } else {
            try {
                addr = AddrHandle.get(cmd);
            } catch (Exception e) {
                Logger.shouldNotHappen("it should have already been checked but still failed", e);
                cb.failed(new Exception("invalid system call"));
                return;
            }
        }
        byte[] pass = null;
        if (type.equals("resp")) {
            pass = cmd.args.get(Param.pass).getBytes();
        }

        // start
        try {
            if (type.equals("resp")) {
                Application.get().respControllerHolder.add(cmd.resource.alias, addr, pass);
            } else if (type.equals("http")) {
                Application.get().httpControllerHolder.add(cmd.resource.alias, addr);
            } else {
                assert type.equals("docker-network-plugin");
                Application.get().dockerNetworkPluginControllerHolder.add(cmd.resource.alias, (UDSPath) addr);
            }
        } catch (AlreadyExistException e) {
            cb.failed(new XException("the " + type.toUpperCase() + "Controller is already started"));
            return;
        } catch (IOException e) {
            cb.failed(new Exception("got exception when starting " + type + "-controller: " + Utils.formatErr(e)));
            return;
        }
        cb.succeeded(new CmdResult());
    }

    private static void handleRemoveRespController(String[] arr, Callback<CmdResult, ? super Exception> cb) {
        try {
            Application.get().respControllerHolder.removeAndStop(arr[2]);
        } catch (NotFoundException e) {
            cb.failed(e);
        }
        cb.succeeded(new CmdResult());
    }

    private static void handleRemoveHttpController(String[] arr, Callback<CmdResult, ? super Exception> cb) {
        try {
            Application.get().httpControllerHolder.removeAndStop(arr[2]);
        } catch (NotFoundException e) {
            cb.failed(e);
        }
        cb.succeeded(new CmdResult());
    }

    private static void handleRemoveDockerNetworkPluginController(String[] arr, Callback<CmdResult, ? super Exception> cb) {
        try {
            Application.get().dockerNetworkPluginControllerHolder.removeAndStop(arr[2]);
        } catch (NotFoundException e) {
            cb.failed(e);
        }
        cb.succeeded(new CmdResult());
    }

    private static void handleListController(String type, boolean detail, Callback<CmdResult, ? super XException> cb) {
        List<String> names;
        if (type.equals("resp")) {
            RESPControllerHolder h = Application.get().respControllerHolder;
            names = h.names();
        } else if (type.equals("http")) {
            HttpControllerHolder h = Application.get().httpControllerHolder;
            names = h.names();
        } else {
            assert type.equals("docker-network-plugin");
            DockerNetworkPluginControllerHolder h = Application.get().dockerNetworkPluginControllerHolder;
            names = h.names();
        }
        List<Object> controllers = new LinkedList<>();
        StringBuilder sb = new StringBuilder();
        boolean isFirst = true;
        for (String name : names) {
            if (isFirst) isFirst = false;
            else sb.append("\n");

            if (type.equals("resp")) {
                RESPController c;
                try {
                    RESPControllerHolder h = Application.get().respControllerHolder;
                    c = h.get(name);
                } catch (NotFoundException e) {
                    // should not happen if no concurrency. just ignore
                    continue;
                }
                controllers.add(c);
                sb.append(c.alias);
                if (detail) {
                    sb.append(" -> ").append(c.server.id());
                }
            } else if (type.equals("http")) {
                HttpController c;
                try {
                    HttpControllerHolder h = Application.get().httpControllerHolder;
                    c = h.get(name);
                } catch (NotFoundException e) {
                    // should not happen if no concurrency. just ignore
                    continue;
                }
                controllers.add(c);
                sb.append(c.alias);
                if (detail) {
                    sb.append(" -> ").append(c.address.toInetSocketAddress());
                }
            } else {
                //noinspection ConstantConditions
                assert type.equals("docker-network-plugin");
                DockerNetworkPluginController c;
                try {
                    DockerNetworkPluginControllerHolder h = Application.get().dockerNetworkPluginControllerHolder;
                    c = h.get(name);
                } catch (NotFoundException e) {
                    // should not happen if no concurrency. just ignore
                    continue;
                }
                controllers.add(c);
                sb.append(c.alias);
                if (detail) {
                    sb.append(" -> ").append(c.path.path);
                }
            }
        }
        String resps = sb.toString();
        List<String> lines = Arrays.asList(resps.split("\n"));
        cb.succeeded(new CmdResult(controllers, lines, resps));
    }
}

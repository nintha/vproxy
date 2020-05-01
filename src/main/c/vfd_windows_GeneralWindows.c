#include "vfd_windows_GeneralWindows.h"
#include "vfd_windows.h"
#include "exception.h"

JNIEXPORT jboolean JNICALL Java_vfd_windows_GeneralWindows_tapNonBlockingSupported
  (JNIEnv* env, jobject self) {
    return JNI_FALSE;
}

#define GUID_MAX_LEN 256

BOOL findTapGuidByNameInNetworkPanel(JNIEnv* env, char* dev, char* guid) {
    LONG res;
    HKEY network_connections_key;
    res = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                       NETWORK_CONNECTIONS_KEY,
                       0,
                       KEY_READ,
                       &network_connections_key);
    if (res != ERROR_SUCCESS) {
        throwIOExceptionBasedOnLastError(env, "failed to open NETWORK_CONNECTIONS_KEY");
        return FALSE;
    }
    int i = 0;
    while (1) {
        char enum_name[GUID_MAX_LEN];
        char connection_string[256];
        HKEY connection_key;
        WCHAR name_data[256];
        DWORD name_type;
        const WCHAR name_string[] = L"Name";
        DWORD len = sizeof(enum_name);
        res = RegEnumKeyEx(network_connections_key, i++, enum_name, &len,
                           NULL, NULL, NULL, NULL);
        if (res == ERROR_NO_MORE_ITEMS) {
            break;
        } else if (res != ERROR_SUCCESS) {
            throwIOExceptionBasedOnLastError(env, "failed to enumerate on keys");
            return FALSE;
        }
        snprintf(connection_string, sizeof(connection_string), "%s\\%s\\Connection",
                 NETWORK_CONNECTIONS_KEY,
                 enum_name);
        res = RegOpenKeyEx(HKEY_LOCAL_MACHINE, connection_string, 0, KEY_READ, &connection_key);
        if (res != ERROR_SUCCESS) {
            // do not throw error here, simply skip the key
            continue;
        }
        len = sizeof(name_data);
        res = RegQueryValueExW(connection_key, name_string, NULL, &name_type, (LPBYTE) name_data, &len);
        if (res != ERROR_SUCCESS) {
            throwIOExceptionBasedOnLastError(env, "RegQueryValueExW failed");
            return FALSE;
        }
        if (name_type != REG_SZ) {
            continue;
        }
        int n = WideCharToMultiByte(CP_UTF8, 0, name_data, -1, NULL, 0, NULL, NULL);
        char* name = malloc(n);
        WideCharToMultiByte(CP_UTF8, 0, name_data, -1, name, n, NULL, NULL);
        if (strcmp(dev_name, name) == 0) {
            // found
            memcpy(guid, enum_name, sizeof(enum_name));
            return TRUE;
        } else {
            free(name);
        }
        // continue loop
    }
    throwIOException(env, "tap not found");
    return FALSE;
}

BOOL openTapDevice(JNIEnv* env, char* guid, HANDLE* outHandle) {
    char tuntap_device_path[1024];
    sprintf(tuntap_device_path, "%s%s%s", USERMODEDEVICEDIR, guid, TAP_WIN_SUFFIX);
    HANDLE handle = CreateFile(tuntap_device_path,
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    0,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_SYSTEM,
                    0);
    if (handle == INVALID_HANDLE_VALUE) {
        throwIOExceptionBasedOnLastError(env, "open tap device failed");
        return FALSE;
    }
    *outHandle = handle;
    return TRUE;
}

BOOL plugCableToTabDevice(JNIEnv* env, HANDLE handle) {
    ULONG x = TRUE;
    DWORD len;
    if (DeviceIoControl(handle, TAP_WIN_IOCTL_SET_MEDIA_STATUS, &x, sizeof(x), &x, sizeof(x), &len, NULL)) {
        return TRUE;
    } else {
        throwIOExceptionBasedOnLastError(env, "setting device to CONNECTED failed");
        return FALSE;
    }
}

JNIEXPORT jlong JNICALL Java_vfd_windows_GeneralWindows_createTapFD
  (JNIEnv* env, jobject self, jstring dev) {
    const char* devChars = (*env)->GetStringUTFChars(env, dev, NULL);

    BOOL status;
    char guid[GUID_MAX_LEN];
    HANDLE handle;
    status = findTapGuidByNameInNetworkPanel(env, devChars, guid);
    if (!status) {
        (*env)->ReleaseStringUTFChars(env, dev, devChars);
        return 0;
    }
    status = openTapDevice(env, guid, &handle);
    if (!status) {
        (*env)->ReleaseStringUTFChars(env, dev, devChars);
        return 0;
    }
    status = plugCableToTabDevice(env, handle);
    if (!status) {
        (*env)->ReleaseStringUTFChars(env, dev, devChars);
        CloseHandle(handle);
        return 0;
    }
    (*env)->ReleaseStringUTFChars(env, dev, devChars);
    return (jlong) handle;
}

JNIEXPORT void JNICALL Java_vfd_windows_GeneralWindows_closeHandle
  (JNIEnv* env, jobject self, jlong handleJ) {
    HANDLE handle = (HANDLE) handleJ;
    BOOL status = CloseHandle(handle);
    if (!status) {
        throwIOExceptionBasedOnLastError(env, "close failed");
    }
}

JNIEXPORT jint JNICALL Java_vfd_windows_GeneralWindows_read
  (JNIEnv* env, jobject self, jlong handleJ, jobject directBuffer, jint off, jint len) {
    if (len == 0) {
        return 0;
    }
    byte* buf = (*env)->GetDirectBufferAddress(env, directBuffer);
    DWORD n = 0;
    HANDLE handle = (HANDLE) handleJ;
    BOOL status = ReadFile(handle, buf + off, len, &n, NULL);
    if (!status) {
        throwIOExceptionBasedOnLastError(env, "read failed");
        return 0;
    }
    return (jint) n;
}

JNIEXPORT jint JNICALL Java_vfd_windows_GeneralWindows_write
  (JNIEnv* env, jobject self, jlong handleJ, jobject directBuffer, jint off, jint len) {
    if (len == 0) {
        return 0;
    }
    byte* buf = (*env)->GetDirectBufferAddress(env, directBuffer);
    DWORD n = 0;
    HANDLE handle = (HANDLE) handleJ;
    BOOL status = WriteFile(handle, buf + off, len, &n, NULL);
    if (!status) {
        throwIOExceptionBasedOnLastError(env, "write failed");
        return 0;
    }
    return (jint) n;
}

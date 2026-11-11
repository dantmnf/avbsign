#include <errno.h>
#include <fcntl.h>
#include <iconv.h>
#include <jni.h>
#include <linux/fs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

static void throw_io_exception(JNIEnv *env, const char *op, const char *path, int err) {
    char msg[512];
    snprintf(msg, sizeof(msg), "%s (%s): %s", op, path, strerror(err));
    jclass cls = (*env)->FindClass(env, "java/io/IOException");
    if (cls != NULL) {
        (*env)->ThrowNew(env, cls, msg);
    }
}

static char *jstring_to_utf8(JNIEnv *env, jstring jstr) {
    if (jstr == NULL) {
        return NULL;
    }
    jsize len = (*env)->GetStringLength(env, jstr);
    const jchar *chars = (*env)->GetStringChars(env, jstr, NULL);
    if (chars == NULL) {
        return NULL;
    }
    size_t out_cap = (size_t)len * 3;
    char *out = malloc(out_cap + 1);
    if (out == NULL) {
        (*env)->ReleaseStringChars(env, jstr, chars);
        jclass oom = (*env)->FindClass(env, "java/lang/OutOfMemoryError");
        if (oom != NULL) {
            (*env)->ThrowNew(env, oom, "malloc failed");
        }
        return NULL;
    }
    iconv_t cd = iconv_open("UTF-8", "UTF-16LE");
    if (cd == (iconv_t)-1) {
        int err = errno;
        (*env)->ReleaseStringChars(env, jstr, chars);
        free(out);
        throw_io_exception(env, "iconv_open failed", "", err);
        return NULL;
    }
    char *in_buf = (char *)chars;
    size_t in_left = (size_t)len * sizeof(jchar);
    char *out_buf = out;
    size_t out_left = out_cap;
    if (iconv(cd, &in_buf, &in_left, &out_buf, &out_left) == (size_t)-1) {
        int err = errno;
        iconv_close(cd);
        (*env)->ReleaseStringChars(env, jstr, chars);
        free(out);
        throw_io_exception(env, "iconv failed", "", err);
        return NULL;
    }
    *out_buf = '\0';
    iconv_close(cd);
    (*env)->ReleaseStringChars(env, jstr, chars);
    return out;
}

JNIEXPORT jboolean JNICALL
Java_xyz_cirno_avbsign_AvbTool_nativeIsBlockDeviceReadOnly(JNIEnv *env, jclass clazz, jstring jpath) {
    (void)clazz;
    char *path = jstring_to_utf8(env, jpath);
    if (path == NULL) {
        return JNI_FALSE;
    }
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        throw_io_exception(env, "open failed", path, errno);
        free(path);
        return JNI_FALSE;
    }
    int ro = 0;
    if (ioctl(fd, BLKROGET, &ro) < 0) {
        int err = errno;
        close(fd);
        throw_io_exception(env, "ioctl(BLKROGET) failed", path, err);
        free(path);
        return JNI_FALSE;
    }
    close(fd);
    free(path);
    return ro != 0 ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT void JNICALL
Java_xyz_cirno_avbsign_AvbTool_nativeSetBlockDeviceReadOnly(JNIEnv *env, jclass clazz, jstring jpath, jboolean readOnly) {
    (void)clazz;
    char *path = jstring_to_utf8(env, jpath);
    if (path == NULL) {
        return;
    }
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        throw_io_exception(env, "open failed", path, errno);
        free(path);
        return;
    }
    int ro = readOnly ? 1 : 0;
    if (ioctl(fd, BLKROSET, &ro) < 0) {
        int err = errno;
        close(fd);
        throw_io_exception(env, "ioctl(BLKROSET) failed", path, err);
        free(path);
        return;
    }
    close(fd);
    free(path);
}

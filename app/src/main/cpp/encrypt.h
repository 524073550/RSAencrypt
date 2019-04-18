//
// Created by StephenLau on 2019/4/11.
//
#include <android/log.h>

#ifndef ANDROIDTRADERV1_ENCRYPT_H
#define ANDROIDTRADERV1_ENCRYPT_H

#define TAG "encrypt"
//__VA_ARGS__ 是一个可变参数的宏，宏定义中参数列表的最后一个参数为省略号
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)
#define LOGF(...) __android_log_print(ANDROID_LOG_FATAL, TAG ,__VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG ,__VA_ARGS__)


#endif //ANDROIDTRADERV1_NATIVE_LIB_H

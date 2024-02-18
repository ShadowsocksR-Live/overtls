//
//  OverTlsWrapper.m
//  overtls
//
//  Created by ssrlive on 2023/4/23.
//

#import <Foundation/Foundation.h>

#import "OverTlsWrapper.h"
#include "overtls-ffi.h"

@implementation OverTlsWrapper

+ (void)startWithConfig:(NSString *)filePath
                handler:(void (*)(int port, void *ctx))handler
                context:(void *)ctx {
  over_tls_client_run(filePath.UTF8String, Trace, handler, ctx);
}

+ (void)shutdown {
  over_tls_client_stop();
}

+ (void) setLogCallback:(void (*)(int verbosity, const char*, void*))cb context:(void*)ctx {
    typedef void (*p_cb)(enum ArgVerbosity, const char*, void*);
    overtls_set_log_callback((p_cb)cb, ctx);
}

@end

/**
 * md5 header
 *
 * Copyright (C) 2015, ON Semiconductor, all right reserved.
 *
 * @file		md5.h
 * @date		svn:$Date: 2015-09-16 13:16:11 +0900 (2015/09/16 (水)) $
 * @revision	svn:$Revision: 88 $
 * @attention
 **/
#ifndef _MD5_H
#define _MD5_H

typedef struct
{
    unsigned long total[2];
    unsigned long state[4];
    unsigned char buffer[64];
}
md5_context;

void md5_starts( md5_context *ctx );
void md5_update( md5_context *ctx, unsigned char *input, unsigned long length );
void md5_finish( md5_context *ctx, unsigned char digest[16] );

#endif 

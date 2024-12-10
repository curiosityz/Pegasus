/*
    MyStreams.h
    Header file for the MyStreams module.
    Provides API for stream-like structures and functions.
*/

#pragma once

#include <windows.h>

// Initial size of buffer
#define MY_STREAM_INIT_SIZE 102400

// Pseudo-stream definition
typedef struct _MY_STREAM MY_STREAM;
typedef struct _MY_STREAM {
    LPVOID pData;            // Data buffer pointer
    SIZE_T lDataLen;         // Amount of data currently in buffer
    SIZE_T lMaxBufferLen;    // Max amount of data currently able to fit in buffer

    // Exported methods
    VOID (*msFreeStream)(MY_STREAM *pStream);
    VOID (*msWriteStream)(MY_STREAM *pStream, LPVOID pData, SIZE_T lDataLen);
    SIZE_T (*msReadStream)(MY_STREAM *pStream, LPVOID pReadBuffer, SIZE_T lReadBufferLen);
} MY_STREAM, *PMY_STREAM;

#ifdef __cplusplus
extern "C" {
#endif

// APIs
BOOL msInitStream_(MY_STREAM *pStream);

#ifdef _DEBUG
BOOL msInitStream_dbg(LPSTR szCaller, MY_STREAM *pStream);
#endif

#ifdef __cplusplus
}
#endif

#ifndef _DEBUG
#define msInitStream msInitStream_
#else
#define msInitStream(ms) msInitStream_dbg(__FUNCTION__"@"QUOTE(__LINE__), ms)
#endif

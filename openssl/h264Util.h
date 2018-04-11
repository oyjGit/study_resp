#ifndef __H264_UTIL__
#define __H264_UTIL__

/*
����h264�ļ��Ĵ洢��ʽ��sps,pps,sei,i,p...p,sps,pps.......ÿ��nalu����ǰ�����ĸ��ֽڵ���ʼ�롣
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "readFile.h"


typedef struct _h264Helper
{
	char*	data;//����ָ��
	int		dataLen;//���ݳ���
	int		startCodeLen;//nalu��ʼͷ����
	int		naluType;//֡����
	int		loop;//�Ƿ�ѭ����
	int		dataReadDone;//�������ݶ�ȡ���
	readFileHelper fileHelper;
}h264Helper;

#ifdef __cplusplus
extern "C"{
#endif

int h264HelperInit(h264Helper* helper,const char* fileName,int isLoop);

int h264HelperFree(h264Helper* helper);

//����0��ʾ�ɹ�������ʧ��
int getH264Frame(h264Helper* helper);


#ifdef __cplusplus
}
#endif

#endif
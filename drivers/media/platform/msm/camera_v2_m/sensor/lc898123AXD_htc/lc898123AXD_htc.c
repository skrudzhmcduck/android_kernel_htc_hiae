/* Copyright (c) 2012-2013, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include "../msm_sensor.h"

#include "lc898123AXD_htc.h"
#include "lc898123AXD_Ois.h"
#include "lc898123AXD_md5.h"


static struct msm_sensor_ctrl_t *g_s_ctrl = NULL;
static struct GYRO_gpio_info *g_GYRO_info = NULL;

static int GYRO_Cali_init (struct msm_sensor_ctrl_t *s_ctrl)
{
    pr_info("[OIS_Cali]%s:E\n", __func__);

    g_GYRO_info = kzalloc(sizeof(struct GYRO_gpio_info), GFP_ATOMIC);
    g_GYRO_info->flash_rw = of_get_named_gpio((&s_ctrl->pdev->dev)->of_node,"flash_rw",0);
    pr_info("[OIS_Cali]flash_rw %d\n", g_GYRO_info->flash_rw);
	if (g_GYRO_info->flash_rw < 0) {
		pr_err("[OIS_Cali]%s:%d flash_rw rc %d\n", __func__, __LINE__, g_GYRO_info->flash_rw);
	}
    return 0;
}

int GYRO_Cali_release(void)
{
	pr_info("[OIS_Cali]%s\n", __func__);

	kfree(g_GYRO_info);

	return 0;
}

unsigned char	htc_RdStatus( unsigned char UcStBitChk )
{
	unsigned int	UlReadVal ;

	RamRead32A( CMD_READ_STATUS , &UlReadVal );
	if( UcStBitChk ){
		UlReadVal &= READ_STATUS_INI ;
	}
	if( !UlReadVal ){
		return( SUCCESS );
	}else{
		return( FAILURE );
	}
}
#define		read_FW					0x8000

unsigned char htc_GyroReCalib(struct msm_sensor_ctrl_t *s_ctrl)
{
	unsigned char	UcSndDat = 1 ;
	unsigned int	UlRcvDat;
	unsigned int	UlFctryX, UlFctryY;
	unsigned int	UlCurrX, UlCurrY;
	unsigned int	UlGofX, UlGofY ;
	stReCalib pReCalib = {0};
    g_s_ctrl = s_ctrl;
	pr_info("[OIS_Cali]%s:E\n", __func__);

    if (g_s_ctrl == NULL)
        return -1;

    GYRO_Cali_init(s_ctrl);

	RamWrite32A( CMD_CALIBRATION , 0x00000000 ) ;

	while( UcSndDat ) {
		UcSndDat = htc_RdStatus(1);
	}
	RamRead32A( CMD_CALIBRATION , &UlRcvDat ) ;
	UcSndDat = (unsigned char)(UlRcvDat >> 24);
	
	FlashNVR_ReadData_ByteA( CALIBRATION_DATA_ADDRESS, FLASH_SECTOR_BUFFER, 256	);

	GET_UINT32( UlCurrX,											GYRO_OFFSET_VALUE_X ) ;
	GET_UINT32( UlCurrY,											GYRO_OFFSET_VALUE_Y ) ;
	GET_UINT32( UlFctryX,											GYRO_OFFSET_FCTRY_X ) ;
	GET_UINT32( UlFctryY,											GYRO_OFFSET_FCTRY_Y ) ;
	if( UlFctryX == 0xFFFFFFFF )
		pReCalib.SsFctryOffX = (UlCurrX >> 16) ;
	else
		pReCalib.SsFctryOffX = (UlFctryX >> 16) ;

	if( UlFctryY == 0xFFFFFFFF )
		pReCalib.SsFctryOffY = (UlCurrY >> 16) ;
	else
		pReCalib.SsFctryOffY = (UlFctryY >> 16) ;

	RamRead32A(  GYRO_RAM_GXOFFZ , &UlGofX ) ;
	RamRead32A(  GYRO_RAM_GYOFFZ , &UlGofY ) ;

	pReCalib.SsRecalOffX = (UlGofX >> 16) ;
	pReCalib.SsRecalOffY = (UlGofY >> 16) ;
	pReCalib.SsDiffX = ((short)pReCalib.SsFctryOffX - (short)pReCalib.SsRecalOffX) > 0 ?  ((short)pReCalib.SsFctryOffX - (short)pReCalib.SsRecalOffX) : ((short)pReCalib.SsRecalOffX - (short)pReCalib.SsFctryOffX);
	pReCalib.SsDiffY = ((short)pReCalib.SsFctryOffY - (short)pReCalib.SsRecalOffY) > 0 ?  ((short)pReCalib.SsFctryOffY - (short)pReCalib.SsRecalOffY) : ((short)pReCalib.SsRecalOffY - (short)pReCalib.SsFctryOffY);
    pr_info("[OIS_Cali]%s: %u, pReCalib->SsDiffX = %d (%#x), pReCalib->SsDiffY = %d (%#x)\n", __func__, UcSndDat, pReCalib.SsDiffX, pReCalib.SsDiffX, pReCalib.SsDiffY, pReCalib.SsDiffY);

    if (UcSndDat != 0)
    {
        GYRO_Cali_release();
		return (int)UcSndDat;
	}
	else if(pReCalib.SsDiffX >= 0x1000 || pReCalib.SsDiffY >= 0x1000)
	{
        GYRO_Cali_release();
		return -1;
	}
	else
		return (int)UcSndDat;
}

short htc_WrGyroOffsetData( void )
{
	unsigned int	UlFctryX, UlFctryY;
	unsigned int	UlCurrX, UlCurrY;
	unsigned int	UlGofX, UlGofY;
	unsigned short iRetVal = 0;
    pr_info("[OIS_Cali]%s: E\n", __func__);
	RamRead32A(  GYRO_RAM_GXOFFZ , &UlGofX ) ;
	RamWrite32A( StCaliData_SiGyroOffset_X ,	UlGofX ) ;
	
	RamRead32A(  GYRO_RAM_GYOFFZ , &UlGofY ) ;
	RamWrite32A( StCaliData_SiGyroOffset_Y ,	UlGofY ) ;

	
	
	
	
	
	
	iRetVal = Calibration_VerifyUpdate_PreRead();
	if( iRetVal != 0 ) return( iRetVal );

	GET_UINT32( UlCurrX,											GYRO_OFFSET_VALUE_X ) ;
	GET_UINT32( UlCurrY,											GYRO_OFFSET_VALUE_Y ) ;
	GET_UINT32( UlFctryX,											GYRO_OFFSET_FCTRY_X ) ;
	GET_UINT32( UlFctryY,											GYRO_OFFSET_FCTRY_Y ) ;
	if( UlFctryX == 0xFFFFFFFF )
		PUT_UINT32( UlCurrX,										GYRO_OFFSET_FCTRY_X	) ;

	if( UlFctryY == 0xFFFFFFFF )
		PUT_UINT32( UlCurrY,										GYRO_OFFSET_FCTRY_Y	) ;

	PUT_UINT32( UlGofX,											GYRO_OFFSET_VALUE_X	) ;
	PUT_UINT32( UlGofY,											GYRO_OFFSET_VALUE_Y	) ;


	
	iRetVal = Calibration_VerifyUpdate();

    pr_info("[OIS_Cali]%s: X  iRetVal = %d\n", __func__, iRetVal);
    GYRO_Cali_release();
	return iRetVal;
}

unsigned short Calibration_VerifyUpdate_PreRead( void )
{
	unsigned char UcCnt;
	unsigned short UsNum;
	unsigned int UlReadVal[4];

	
	FlashResetRelease();		
	
	FlashAutoConfig();
	
	IOWrite32A( FLASHROM_TPGS, 118 );			
	IOWrite32A( FLASHROM_TPROG , 70 );			
	IOWrite32A( FLASHROM_TERASES , 92 );		
	IOWrite32A( FLASHROM_ADR , 0x00010000 );	
	IOWrite32A( FLASHROM_ACSCNT , (256 -1) );	
	IOWrite32A( FLASHROM_CMD , 1 );		
	RamWrite32A( CMD_IO_ADR_ACCESS, FLASHROM_RDAT ) ;
	for ( UsNum = 0; UsNum <= 0xFF; UsNum+=4 )
	{
		IORead4times32A( UlReadVal );
		for (UcCnt= 0 ; UcCnt< 4 ; UcCnt++){
			NVR0_Backup[UsNum + UcCnt]   = (unsigned char)UlReadVal[UcCnt];
			FLASH_SECTOR_BUFFER[UsNum + UcCnt]	     = (unsigned char)(UlReadVal[UcCnt]>>8);
			NVR2_Backup[UsNum + UcCnt]   = (unsigned char)(UlReadVal[UcCnt]>>16);
		}
	}
	
	IOWrite32A( FLASHROM_WPB , 1 );							
	WPBCtrl(WPB_OFF) ;										
	if ( ReadWPB() != 1 ){ FlashReset(); return ( 5 );}		

	IOWrite32A( FLASHROM_ADR , 0x00010000 );				
	IOWrite32A( FLASHROM_SEL , 0x06  );			
	IOWrite32A( FLASHROM_CMD , 4 );							
	
	return( 0 );
}

void FlashResetRelease(void)
{
	unsigned int UlReadVal;
	
	IORead32A( SOFTRESET	, &UlReadVal ) ;
	RamWrite32A( CMD_IO_DAT_ACCESS, (UlReadVal | 0x00000010) ) ;	
}

void FlashAutoConfig( void )
{
	IOWrite32A( FLASHROM_WPB	, 1 );			
	IOWrite32A( FLASHROM_SEL	, 7 );			
	IOWrite32A( FLASHROM_ADR	, 0x00010100 );	
	IOWrite32A( FLASHROM_ACSCNT	, 7 );			
	IOWrite32A( FLASHROM_CMD	, 7 );			
}

unsigned short Calibration_VerifyUpdate( void )
{
	unsigned char UcCnt;
	unsigned short UsNum;
	unsigned char UcNvrData[2];
	unsigned int UlReadVal[4];
    md5_context ctx;
	CRC_Reg = 0x0000ffff;
	
	for ( UsNum = 0; UsNum <= 0xFF; UsNum++ )	
	{
		
		UcNvrData[0] = NVR0_Backup[ UsNum ];	
		UcNvrData[1] = FLASH_SECTOR_BUFFER[ UsNum ];		
		CRC16_main( UcNvrData, 2 );
	}
	NVR2_Backup[ 0x22 ] = (unsigned char)(CRC_Reg>>8);
	NVR2_Backup[ 0x23 ] = (unsigned char)CRC_Reg;
	md5_starts( &ctx );
	for ( UsNum = 0; UsNum <= 0xFF; UsNum++ )	
	{
		
		UcNvrData[0] = FLASH_SECTOR_BUFFER[ UsNum ];		
		UcNvrData[1] = NVR0_Backup[ UsNum ];	
		md5_update( &ctx, UcNvrData, 2);
	}
	md5_finish( &ctx, &(NVR2_Backup[ 0x10 ]) );
	
	RamWrite32A( CMD_IO_ADR_ACCESS, FLASHROM_INT ) ;	
	for ( UsNum  = 0; UsNum  < 10; UsNum ++ )						
	{
		RamRead32A(  CMD_IO_DAT_ACCESS, UlReadVal ) ;
		if( !(UlReadVal[0] ==  0x80) ){
			break;
		}
		WitTim( 2 );
	}
	IOWrite32A( FLASHROM_ACSCNT , 0 );						
	IOWrite32A( FLASHROM_ADR , 0x00010000 );				
	for ( UsNum = 0; UsNum <= 0x7F; UsNum++ )				
	{
		IOWriteDouble32A( FLASHROM_WDAT, ((unsigned int)(NVR2_Backup[UsNum])<<16)+((unsigned int)(FLASH_SECTOR_BUFFER[UsNum])<<8),
						  FLASHROM_CMD,   2 );	
		
	}
	IOWrite32A( FLASHROM_ADR , 0x00010000 + 0x80 );			
	for ( UsNum = 0; UsNum <= 0x7F; UsNum++ )				
	{
		IOWriteDouble32A( FLASHROM_WDAT, ((unsigned int)(NVR2_Backup[UsNum+0x80])<<16)+((unsigned int)(FLASH_SECTOR_BUFFER[UsNum+0x80])<<8),
					 	  FLASHROM_CMD , 2 );	
		
	}
	IOWrite32A( FLASHROM_WPB, 0  );							
	WPBCtrl(WPB_ON) ;										
	IOWrite32A( FLASHROM_ADR, 0x00010000  );				
	IOWrite32A( FLASHROM_ACSCNT, (256 -1)  );				
	IOWrite32A( FLASHROM_CMD , 1  );						

	RamWrite32A( CMD_IO_ADR_ACCESS, FLASHROM_RDAT ) ;
	for ( UsNum = 0; UsNum <= 0xFF; UsNum+=4 )
	{
		IORead4times32A( UlReadVal )  ;
		for ( UcCnt= 0; UcCnt< 4; UcCnt++ )
		{
			if ( (unsigned char)(UlReadVal[UcCnt]  >>8  ) != FLASH_SECTOR_BUFFER[UsNum + UcCnt] ){	FlashReset();	return(-1); }
			if ( (unsigned char)(UlReadVal[UcCnt]  >>16 ) != NVR2_Backup[UsNum + UcCnt] )		 {	FlashReset();	return(-1); }
		}
	}
	
	FlashReset();
		
	return ( 0 );
}

void IOWrite32A( unsigned int IOadrs, unsigned int IOdata )
{
#ifdef __EXTRA_E0_COMMAND__
	unsigned char UcBuf[9];
	UcBuf[0] = 0xE8;
	UcBuf[1] = (unsigned char)(IOdata >> 24);
	UcBuf[2] = (unsigned char)(IOdata >> 16);
	UcBuf[3] = (unsigned char)(IOdata >> 8);
	UcBuf[4] = (unsigned char)(IOdata >> 0);
	UcBuf[5] = (unsigned char)(IOadrs >> 16);
	UcBuf[6] = (unsigned char)(IOadrs >> 8);
	UcBuf[7] = (unsigned char)(IOadrs >> 0);
	CntWrt( UcBuf, 8 ) ;
#else
	RamWrite32A( CMD_IO_ADR_ACCESS, IOadrs ) ;
	RamWrite32A( CMD_IO_DAT_ACCESS, IOdata ) ;
#endif	
};

void IORead32A( unsigned int IOadrs, unsigned int *IOdata )
{
	RamWrite32A( CMD_IO_ADR_ACCESS, IOadrs ) ;
	RamRead32A ( CMD_IO_DAT_ACCESS, IOdata ) ;
};

void IORead4times32A( unsigned int* Dat )
{
#ifdef __EXTRA_E0_COMMAND__
	UINT8 UcBuf[16];
	CntRd( 0xE8, UcBuf, 16 )  ;
	
	Dat[0] = ((UINT32)UcBuf[0]<<24) | ((UINT32)UcBuf[1]<<16) | ((UINT32)UcBuf[2]<<8) | (UINT32)UcBuf[3] ;
	Dat[1] = ((UINT32)UcBuf[4]<<24) | ((UINT32)UcBuf[5]<<16) | ((UINT32)UcBuf[6]<<8) | (UINT32)UcBuf[7] ;
	Dat[2] = ((UINT32)UcBuf[8]<<24) | ((UINT32)UcBuf[9]<<16) | ((UINT32)UcBuf[10]<<8) | (UINT32)UcBuf[11] ;
	Dat[3] = ((UINT32)UcBuf[12]<<24) | ((UINT32)UcBuf[13]<<16) | ((UINT32)UcBuf[14]<<8) | (UINT32)UcBuf[15] ;	


#else	
	RamRead32A( CMD_IO_DAT_ACCESS , &Dat[0] ) ;
	RamRead32A( CMD_IO_DAT_ACCESS , &Dat[1] ) ;
	RamRead32A( CMD_IO_DAT_ACCESS , &Dat[2] ) ;
	RamRead32A( CMD_IO_DAT_ACCESS , &Dat[3] ) ;
#endif
}

void CRC16_main( unsigned char *p, int Num )
{
	unsigned int tmp0, tmp5, tmp12;
	unsigned int temp, data;
	int i = 0, j = 0;

	for(i=0 ; i<Num ; i++) {
		temp = (unsigned int)*p++;		

		for(j=0 ; j<8 ; j++) {
			data = temp & 0x00000001;	
			temp = temp >> 1;

            tmp0 = ((CRC_Reg >> 15) ^ data) & 0x00000001;
            tmp5 = (((tmp0 << 4) ^ CRC_Reg) & 0x00000010) << 1;
            tmp12 = (((tmp0 << 11) ^ CRC_Reg) & 0x00000800) << 1;
            CRC_Reg = (CRC_Reg << 1) & 0x0000efde;
            CRC_Reg = CRC_Reg | tmp0 | tmp5 | tmp12;
		}
	}
}

void IOWriteDouble32A( unsigned int IOadrs1, unsigned int IOdata1, unsigned int IOadrs2, unsigned int IOdata2 )
{
#ifdef __EXTRA_E0_COMMAND__
	unsigned char UcBuf[15];
	UcBuf[0] = 0xE8;
	UcBuf[1] = (UINT8)(IOdata1 >> 24);
	UcBuf[2] = (UINT8)(IOdata1 >> 16);
	UcBuf[3] = (UINT8)(IOdata1 >> 8);
	UcBuf[4] = (UINT8)(IOdata1 >> 0);
	UcBuf[5] = (UINT8)(IOadrs1 >> 16);
	UcBuf[6] = (UINT8)(IOadrs1 >> 8);
	UcBuf[7] = (UINT8)(IOadrs1 >> 0);
	UcBuf[8] = (UINT8)(IOdata2 >> 24);
	UcBuf[9] = (UINT8)(IOdata2 >> 16);
	UcBuf[10] = (UINT8)(IOdata2 >> 8);
	UcBuf[11] = (UINT8)(IOdata2 >> 0);
	UcBuf[12] = (UINT8)(IOadrs2 >> 16);
	UcBuf[13] = (UINT8)(IOadrs2 >> 8);
	UcBuf[14] = (UINT8)(IOadrs2 >> 0);
	CntWrt( UcBuf, 15 ) ;
#else
	RamWrite32A( CMD_IO_ADR_ACCESS, IOadrs1 ) ;
	RamWrite32A( CMD_IO_DAT_ACCESS, IOdata1 ) ;					
	RamWrite32A( CMD_IO_ADR_ACCESS, IOadrs2 ) ;
	RamWrite32A( CMD_IO_DAT_ACCESS, IOdata2 ) ;					
#endif	
};

void FlashNVR_ReadData_ByteA( unsigned short SetAddress, unsigned char * ReadPtr, unsigned short Num )
{
	FlashNVR_ReadData_Byte( MakeNVRSelIdx(SetAddress), (unsigned char)(SetAddress & 0xFF), ReadPtr, Num ) ;
}

unsigned short MakeNVRSelIdx( unsigned short UsAddress )
{
	
	
	
	return ((UsAddress >> 8) & 0x03);
}

unsigned char ReadWPB( void )

{
#ifdef __OIS_TYPE_XC__					
	return ( 1 ) ;
#else		
#if 0
	UINT32	UlReadVal, UlCnt=0;
#else
    unsigned int UlReadVal, UlCnt=0;
#endif
	do{
		RamWrite32A( CMD_IO_ADR_ACCESS, IOPLEVR ) ;		
		RamRead32A ( CMD_IO_DAT_ACCESS, &UlReadVal ) ;
        pr_info("%s:UlReadVal = %u UlCnt = %u \n", __func__, UlReadVal, UlCnt);
		if( (UlReadVal & 0x0400) != 0 )	return ( 1 ) ;
		WitTim( 1 );		
	}while ( UlCnt++ < 10 );
    pr_info("[OIS_Cali]%s:return 0  \n", __func__);

	return ( 0 );
#endif
}

void WitTim( unsigned short	UsWitTim )
{
    mdelay(UsWitTim);
}

void RamWrite32A( unsigned short RamAddr, unsigned int RamData )
{
	int rc = 0;
	uint8_t data[4] = {0,0,0,0};
	struct msm_sensor_ctrl_t *s_ctrl = g_s_ctrl;

	data[0] = (RamData >> 24) & 0xFF;
	data[1] = (RamData >> 16) & 0xFF;
	data[2] = (RamData >> 8)  & 0xFF;
	data[3] = (RamData) & 0xFF;
	
	rc = s_ctrl->sensor_i2c_client->i2c_func_tbl->i2c_write_seq(
		s_ctrl->sensor_i2c_client, RamAddr, &data[0], 4);
	if (rc < 0)
		pr_err("[OIS] %s : write failed\n", __func__);
}

void RamRead32A( unsigned short RamAddr, unsigned int * ReadData )
{
	int rc = 0;
	uint8_t buf[4] = {0,0,0,0};
	struct msm_sensor_ctrl_t *s_ctrl = g_s_ctrl;

	rc = s_ctrl->sensor_i2c_client->i2c_func_tbl->i2c_read_seq(
		s_ctrl->sensor_i2c_client, RamAddr, &buf[0], 4);
	if (rc < 0)
		pr_err("[OIS] %s : read failed\n", __func__);
	else
		*ReadData = (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];
}
 
unsigned short MakeNVRSel( unsigned short UsAddress )
{
        
        
        
        return 1 << ((UsAddress >> 8) & 0x03);
}
 
unsigned int MakeNVRDat( unsigned short UsAddress, unsigned char UcData )
{
        
        
        
        return (unsigned int)UcData << (((UsAddress >> 8) & 0x03) * 8);
}
 
unsigned char MakeDatNVR( unsigned short UsAddress, unsigned int UlData )
{
        return (unsigned char)((UlData >> (((UsAddress >> 8) & 0x03) * 8)) & 0xFF);
}
 
void WPBCtrl( unsigned char UcCtrl )
{
    int rc = 0;
#if 1
    pr_info("[OIS_Cali]%s:E 1\n", __func__);
        if (UcCtrl == 0)
        {       
            rc = gpio_request_one(g_GYRO_info->flash_rw, 0, "flash_rw");
            pr_info("[OIS_Cali]%s : Write Protect ON  flash_rw = %d\n", __func__, g_GYRO_info->flash_rw);
            if (rc < 0)
                pr_err("[OIS_Cali]%s:GPIO(%d) request failed", __func__,g_GYRO_info->flash_rw);

            if (g_GYRO_info->flash_rw != 0){
                gpio_set_value_cansleep(g_GYRO_info->flash_rw,0);
                mdelay(5);
                gpio_free(g_GYRO_info->flash_rw);
            }
            else
                pr_err("[OIS_Cali]%s:GPIO(%d) g_GYRO_info->flash_rw failed\n", __func__, g_GYRO_info->flash_rw);

            pr_info("[OIS_Cali]%s:Write Protect ON \n", __func__);
        } else {
                
            rc = gpio_request_one(g_GYRO_info->flash_rw, 0, "flash_rw");
                pr_info("[OIS_Cali]%s:Write Protect OFF  flash_rw = %d\n", __func__,g_GYRO_info->flash_rw);
            if (rc < 0)
                pr_err("[OIS_Cali]%s:GPIO(%d) request failed", __func__,g_GYRO_info->flash_rw);

            if (g_GYRO_info->flash_rw != 0){
                gpio_set_value_cansleep(g_GYRO_info->flash_rw,1);
                mdelay(5);
                gpio_free(g_GYRO_info->flash_rw);
            }
            else
                pr_err("[OIS_Cali]%s:GPIO(%d) g_GYRO_info->flash_rw failed\n", __func__, g_GYRO_info->flash_rw);

            pr_info("[OIS_Cali]%s:Write Protect OFF \n", __func__);
        }
#else
    pr_info("[OIS_Cali]%s:E 2\n", __func__);
        if (UcCtrl == 0)
        {       
            rc = gpio_request_one(g_GYRO_info->flash_rw, 0, "flash_rw");
            pr_info("[OIS_Cali]%s : Write Protect ON  flash_rw = %d\n", __func__, g_GYRO_info->flash_rw);
            if (rc < 0)
                pr_err("[OIS_Cali]%s:GPIO(%d) request failed", __func__,g_GYRO_info->flash_rw);

            if (g_GYRO_info->flash_rw != 0){
                gpio_direction_output(g_GYRO_info->flash_rw, 0);
                mdelay(5);
                gpio_free(g_GYRO_info->flash_rw);
            }
            else
                pr_err("[OIS_Cali]%s:GPIO(%d) g_GYRO_info->flash_rw failed\n", __func__, g_GYRO_info->flash_rw);

            pr_info("[OIS_Cali]%s:Write Protect ON \n", __func__);
        } else {
                
            rc = gpio_request_one(g_GYRO_info->flash_rw, 0, "flash_rw");
                pr_info("[OIS_Cali]%s:Write Protect OFF  flash_rw = %d\n", __func__,g_GYRO_info->flash_rw);
            if (rc < 0)
                pr_err("[OIS_Cali]%s:GPIO(%d) request failed", __func__,g_GYRO_info->flash_rw);

            if (g_GYRO_info->flash_rw != 0){
                gpio_direction_output(g_GYRO_info->flash_rw, 1);
                mdelay(5);
                gpio_free(g_GYRO_info->flash_rw);
            }
            else
                pr_err("[OIS_Cali]%s:GPIO(%d) g_GYRO_info->flash_rw failed\n", __func__, g_GYRO_info->flash_rw);

            pr_info("[OIS_Cali]%s:Write Protect OFF \n", __func__);
        }
#endif
}








void FlashInitialSetting( char val )
{
	unsigned int UlReadVal = 0;
	int i;

	
	RamWrite32A( CMD_IO_ADR_ACCESS, CVER_123 ) ;
	RamRead32A(  CMD_IO_DAT_ACCESS, &UlReadVal ) ;
	if( UlReadVal > 0xB4 ) {
		return ;
	}

	
	RamWrite32A( CMD_IO_ADR_ACCESS, SOFTRESET );
	RamRead32A ( CMD_IO_DAT_ACCESS, &UlReadVal );
	UlReadVal |= 0x00000010;									
	
	RamWrite32A( CMD_IO_DAT_ACCESS, UlReadVal );

	
	if( val ) {
		RamWrite32A( CMD_IO_ADR_ACCESS, FLASHROM_TPGS ) ;
		RamWrite32A( CMD_IO_DAT_ACCESS, 118 ) ;					

		RamWrite32A( CMD_IO_ADR_ACCESS, FLASHROM_TPROG ) ;
		RamWrite32A( CMD_IO_DAT_ACCESS, 70 ) ;					

		RamWrite32A( CMD_IO_ADR_ACCESS, FLASHROM_TERASES ) ;
		RamWrite32A( CMD_IO_DAT_ACCESS, 92 ) ;					

		RamWrite32A( CMD_IO_ADR_ACCESS, FLASHROM_TERASEC ) ;
		RamWrite32A( CMD_IO_DAT_ACCESS, 115 ) ;					

		RamWrite32A( CMD_IO_ADR_ACCESS, FLASHROM_SEL ) ;
		RamWrite32A( CMD_IO_DAT_ACCESS, 7 ) ;

		
		RamWrite32A( CMD_IO_ADR_ACCESS, FLASHROM_ADR ) ;
		RamWrite32A( CMD_IO_DAT_ACCESS, 0x00000000	  ) ;		
		RamWrite32A( CMD_IO_ADR_ACCESS, FLASHROM_ACSCNT ) ;		
		RamWrite32A( CMD_IO_DAT_ACCESS, 0 ) ;
		RamWrite32A( CMD_IO_ADR_ACCESS, FLASHROM_WPB ) ;		
		RamWrite32A( CMD_IO_DAT_ACCESS, 1 ) ;
		WPBCtrl(WPB_OFF) ;										

		for( i = 0; i < 8; i++ )
		{
			RamWrite32A( CMD_IO_ADR_ACCESS, FLASHROM_WDAT ) ;
			RamWrite32A( CMD_IO_DAT_ACCESS, 0xFFFFFFFF ) ; 

			RamWrite32A( CMD_IO_ADR_ACCESS, FLASHROM_CMD ) ;
			RamWrite32A( CMD_IO_DAT_ACCESS, 3) ;  				
		}

		
		RamWrite32A( CMD_IO_ADR_ACCESS, FLASHROM_ADR ) ;
		RamWrite32A( CMD_IO_DAT_ACCESS, 0x00010100	  ) ;		
		RamWrite32A( CMD_IO_ADR_ACCESS, FLASHROM_ACSCNT ) ;
		RamWrite32A( CMD_IO_DAT_ACCESS, 7 ) ;

		RamWrite32A( CMD_IO_ADR_ACCESS, FLASHROM_CMD ) ;
		RamWrite32A( CMD_IO_DAT_ACCESS, 7 ) ;  					

		RamWrite32A( CMD_IO_ADR_ACCESS, FLASHROM_SEL ) ;		
		RamWrite32A( CMD_IO_DAT_ACCESS, 0 ) ;

		RamWrite32A( CMD_IO_ADR_ACCESS, FLASHROM_WPB ) ;		
		RamWrite32A( CMD_IO_DAT_ACCESS, 0 ) ;
		WPBCtrl(WPB_ON) ;										
	}
}



void FlashReset(void)
{
	unsigned int UlReadVal = 0;

	
	RamWrite32A( CMD_IO_ADR_ACCESS, CVER_123 ) ;
	RamRead32A(  CMD_IO_DAT_ACCESS, &UlReadVal ) ;
	if( UlReadVal > 0xB4 ) {
		return ;
	}

	RamWrite32A( CMD_IO_ADR_ACCESS, FLASHROM_SEL ) ;			
	RamWrite32A( CMD_IO_DAT_ACCESS, 0 ) ;

	
	RamWrite32A( CMD_IO_ADR_ACCESS, SOFTRESET ) ;
	RamRead32A ( CMD_IO_DAT_ACCESS, &UlReadVal ) ;
	UlReadVal &= ~0x00000010;									

	RamWrite32A( CMD_IO_DAT_ACCESS, UlReadVal ) ;
}


int FlashNVRSectorErase_Byte( unsigned short SetAddress )
{
	unsigned char UcCnt;
	unsigned int UlReadVal = 0;
	
	FlashInitialSetting(1);										

	
	RamWrite32A( CMD_IO_ADR_ACCESS, FLASHROM_ADR ) ;			
	RamWrite32A( CMD_IO_DAT_ACCESS, 0x00010000	  ) ;
	
	RamWrite32A( CMD_IO_ADR_ACCESS, FLASHROM_SEL ) ;			
	RamWrite32A( CMD_IO_DAT_ACCESS, MakeNVRSel( SetAddress ) ) ;

	WPBCtrl(WPB_OFF) ;											
	
	RamWrite32A( CMD_IO_ADR_ACCESS, FLASHROM_WPB ) ;			
	RamWrite32A( CMD_IO_DAT_ACCESS, 1 ) ;
	
	
	RamWrite32A( CMD_IO_ADR_ACCESS, FLASHROM_CMD ) ;
	RamWrite32A( CMD_IO_DAT_ACCESS, 4 ) ;						

	RamWrite32A( CMD_IO_ADR_ACCESS, FLASHROM_INT ) ;	
	for ( UcCnt = 0; UcCnt < 100; UcCnt++ )						
	{
		RamRead32A(  CMD_IO_DAT_ACCESS, &UlReadVal ) ;
		if( !(UlReadVal ==  0x80) ){
			break;
		}
	}
	
	RamWrite32A( CMD_IO_ADR_ACCESS, FLASHROM_WPB ) ;			
	RamWrite32A( CMD_IO_DAT_ACCESS,0 ) ;
	WPBCtrl(WPB_ON) ;											

	FlashReset();												
	return ( 0 );
}


void FlashNVR_ReadData_Byte( unsigned char Sel, unsigned char SetAddress, unsigned char * ReadPtr, unsigned short Num )
{
	unsigned short UsNum;
	unsigned int UlReadVal;

	if( Sel >= 3 ) return;
	if( Num == 0 || Num > 256 ) return; 
	if( SetAddress + Num > 256 ) return; 

	
	FlashResetRelease();
	
	FlashAutoConfig();

	
	IOWrite32A( FLASHROM_ACSCNT	,  Num -1 ) ;			
	
	IOWrite32A( FLASHROM_SEL	, (1<<Sel) ) ;			

	
	IOWrite32A( FLASHROM_ADR	, 0x00010000 +  SetAddress ) ;		
	
	IOWrite32A( FLASHROM_CMD	, 1 ) ;					

	RamWrite32A( CMD_IO_ADR_ACCESS, FLASHROM_RDAT ) ;
	for ( UsNum = 0; UsNum < Num; UsNum++ )
	{
		RamRead32A(  CMD_IO_DAT_ACCESS, &UlReadVal ) ;
		ReadPtr[ UsNum ] = (unsigned char)(UlReadVal>>(Sel*8) );
	}

	FlashReset();												
}

#ifdef __CRC_VERIFY__
unsigned int CRC_Reg = 0x0000ffff;
void CRC16_main( unsigned char *p, int Num )
{
	unsigned int tmp0, tmp5, tmp12;
	unsigned int temp, data;

	for(int i=0 ; i<Num ; i++) {
		temp = (unsigned int)*p++;		

		for(int j=0 ; j<8 ; j++) {
			data = temp & 0x00000001;	
			temp = temp >> 1;

            tmp0 = ((CRC_Reg >> 15) ^ data) & 0x00000001;
            tmp5 = (((tmp0 << 4) ^ CRC_Reg) & 0x00000010) << 1;
            tmp12 = (((tmp0 << 11) ^ CRC_Reg) & 0x00000800) << 1;
            CRC_Reg = (CRC_Reg << 1) & 0x0000efde;
            CRC_Reg = CRC_Reg | tmp0 | tmp5 | tmp12;
		}
	}
}

void FlashMainCrc( unsigned char * pCRC )
{
#if 0
	UINT32 UlNum;
	UINT32 UlReadVal;
	UINT8 UcFlaData[3];
#else
	unsigned int UlNum;
	unsigned int UlReadVal;
	unsigned char UcFlaData[3];
#endif
    

	CRC_Reg = 0x0000ffff;
	RamWrite32A( CMD_IO_ADR_ACCESS, FLASHROM_SEL ) ;
	RamWrite32A( CMD_IO_DAT_ACCESS, 7 ) ;
	RamWrite32A( CMD_IO_ADR_ACCESS, FLASHROM_ADR ) ;
	RamWrite32A( CMD_IO_DAT_ACCESS, 0 ) ;
	RamWrite32A( CMD_IO_ADR_ACCESS, FLASHROM_ACSCNT	 ) ;
	RamWrite32A( CMD_IO_DAT_ACCESS, 4096 - 1 ) ;
	RamWrite32A( CMD_IO_ADR_ACCESS, FLASHROM_CMD ) ;
	RamWrite32A( CMD_IO_DAT_ACCESS, 1) ;  					

	RamWrite32A( CMD_IO_ADR_ACCESS, FLASHROM_RDAT ) ;
	for (UlNum= 0 ; UlNum< 4096 ; UlNum++)
	{
		
		RamRead32A( CMD_IO_DAT_ACCESS , &UlReadVal ) ;
		UcFlaData[0] = UlReadVal & 0xFF;
		UcFlaData[1] = (UlReadVal >> 8) & 0xFF;
		UcFlaData[2] = (UlReadVal >> 16) & 0xFF;
		CRC16_main( UcFlaData, 3 );
	}
	pCRC[0] = (UINT8)(CRC_Reg>>8);
	pCRC[1] = (UINT8)CRC_Reg;

}

void FlashNvrCrc( unsigned char * pCRC )
{
#if 0
	UINT32 UlNum;
	UINT32 UlReadVal;	
	UINT8 UcNvrData[2];
#else
	unsigned int UlNum;
	unsigned int UlReadVal;   
	unsigned char UcNvrData[2];
#endif

	CRC_Reg = 0x0000ffff;
	RamWrite32A( CMD_IO_ADR_ACCESS, FLASHROM_SEL ) ;			
	RamWrite32A( CMD_IO_DAT_ACCESS, 3 ) ;						
	RamWrite32A( CMD_IO_ADR_ACCESS, FLASHROM_ADR ) ;			
	RamWrite32A( CMD_IO_DAT_ACCESS, 0x00010000 ) ;
	RamWrite32A( CMD_IO_ADR_ACCESS, FLASHROM_ACSCNT ) ;
	RamWrite32A( CMD_IO_DAT_ACCESS, 256 - 1 ) ;					
	RamWrite32A( CMD_IO_ADR_ACCESS, FLASHROM_CMD ) ;
	RamWrite32A( CMD_IO_DAT_ACCESS, 1 ) ;  						

	RamWrite32A( CMD_IO_ADR_ACCESS, FLASHROM_RDAT ) ;
	for ( UlNum = 0; UlNum < 256; UlNum++ )
	{
		
		RamRead32A( CMD_IO_DAT_ACCESS, &UlReadVal ) ;
		UcNvrData[0] = UlReadVal & 0xFF;				
		UcNvrData[1] = (UlReadVal >> 8) & 0xFF;			
		CRC16_main( UcNvrData, 2 );
	}
	pCRC[0] = (UINT8)(CRC_Reg>>8);
	pCRC[1] = (UINT8)CRC_Reg;

}
#else
void FlashMainMd5( unsigned char * pMD5 )
{
	unsigned int UlNum;
	unsigned int UlReadVal;
	unsigned char UcFlaData[3];

    md5_context ctx;

	md5_starts( &ctx );

	RamWrite32A( CMD_IO_ADR_ACCESS, FLASHROM_SEL ) ;
	RamWrite32A( CMD_IO_DAT_ACCESS, 7 ) ;
	RamWrite32A( CMD_IO_ADR_ACCESS, FLASHROM_ADR ) ;
	RamWrite32A( CMD_IO_DAT_ACCESS, 0 ) ;
	RamWrite32A( CMD_IO_ADR_ACCESS, FLASHROM_ACSCNT	 ) ;
	RamWrite32A( CMD_IO_DAT_ACCESS, 4096 - 1 ) ;
	RamWrite32A( CMD_IO_ADR_ACCESS, FLASHROM_CMD ) ;
	RamWrite32A( CMD_IO_DAT_ACCESS, 1) ;  					

	RamWrite32A( CMD_IO_ADR_ACCESS, FLASHROM_RDAT ) ;		
	for (UlNum= 0 ; UlNum< 4096 ; UlNum++)
	{
		
		RamRead32A( CMD_IO_DAT_ACCESS , &UlReadVal ) ;
		UcFlaData[0] = (UlReadVal >> 16) & 0xFF;
		UcFlaData[1] = (UlReadVal >> 8) & 0xFF;
		UcFlaData[2] = UlReadVal & 0xFF;
		md5_update( &ctx, (unsigned char *)UcFlaData, 3 );
	}
	md5_finish( &ctx, pMD5 );

}

void FlashNvrMd5( unsigned char * pMD5 )
{
	unsigned char UcNvrData[2];
	unsigned int UlNum;
	unsigned int UlReadVal;
    md5_context ctx;

	md5_starts( &ctx );

	RamWrite32A( CMD_IO_ADR_ACCESS, FLASHROM_SEL ) ;			
	RamWrite32A( CMD_IO_DAT_ACCESS, 3 ) ;						
	RamWrite32A( CMD_IO_ADR_ACCESS, FLASHROM_ADR ) ;			
	RamWrite32A( CMD_IO_DAT_ACCESS, 0x00010000 ) ;
	RamWrite32A( CMD_IO_ADR_ACCESS, FLASHROM_ACSCNT ) ;
	RamWrite32A( CMD_IO_DAT_ACCESS, 256 - 1 ) ;					
	RamWrite32A( CMD_IO_ADR_ACCESS, FLASHROM_CMD ) ;
	RamWrite32A( CMD_IO_DAT_ACCESS, 1 ) ;  						

	RamWrite32A( CMD_IO_ADR_ACCESS, FLASHROM_RDAT ) ;
	for ( UlNum = 0; UlNum < 256; UlNum++ )
	{
		
		RamRead32A( CMD_IO_DAT_ACCESS, &UlReadVal ) ;
		UcNvrData[0] = (UlReadVal >> 8) & 0xFF;			
		UcNvrData[1] = UlReadVal & 0xFF;				
		md5_update( &ctx, (unsigned char *)UcNvrData, 2 );
	}
	md5_finish( &ctx, pMD5 );

}
#endif




void	OscStb( void )
{
	RamWrite32A( CMD_IO_ADR_ACCESS , STBOSCPLL ) ;
	RamWrite32A( CMD_IO_DAT_ACCESS , OSC_STB ) ;
}


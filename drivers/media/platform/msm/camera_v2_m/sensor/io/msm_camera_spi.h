/* Copyright (c) 2013-2014, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef __MSM_CAMERA_SPI_H
#define __MSM_CAMERA_SPI_H

#include <linux/spi/spi.h>
#include <media/msm_cam_sensor.h>
#include "msm_camera_i2c.h"

#define MAX_SPI_SIZE 110
#define SPI_DYNAMIC_ALLOC

struct msm_camera_spi_inst {
	uint8_t opcode;		
	uint8_t addr_len;	
	uint8_t dummy_len;	
	uint8_t delay_intv;	
	uint8_t delay_count;	
};

struct msm_spi_write_burst_data {
	u8 data_msb;
	u8 data_lsb;
};

struct msm_spi_write_burst_packet {
	u8 cmd;
	u8 addr_msb;
	u8 addr_lsb;
	struct msm_spi_write_burst_data data_arr[MAX_SPI_SIZE];
};

struct msm_camera_burst_info {
	uint32_t burst_addr;
	uint32_t burst_start;
	uint32_t burst_len;
	uint32_t chunk_size;
};

struct msm_camera_spi_inst_tbl {
	struct msm_camera_spi_inst read;
	struct msm_camera_spi_inst read_seq;
	struct msm_camera_spi_inst query_id;
	struct msm_camera_spi_inst page_program;
	struct msm_camera_spi_inst write_enable;
	struct msm_camera_spi_inst read_status;
	struct msm_camera_spi_inst erase;
};

struct msm_camera_spi_client {
	struct spi_device *spi_master;
	struct msm_camera_spi_inst_tbl cmd_tbl;
	uint8_t device_id0;
	uint8_t device_id1;
	uint8_t mfr_id0;
	uint8_t mfr_id1;
	uint8_t retry_delay;	
	uint8_t retries;	
	uint8_t busy_mask;	
	uint16_t page_size;	
	uint32_t erase_size;	
};

static __always_inline
uint16_t msm_camera_spi_get_hlen(struct msm_camera_spi_inst *inst)
{
	return sizeof(inst->opcode) + inst->addr_len + inst->dummy_len;
}

int32_t msm_camera_spi_read(struct msm_camera_i2c_client *client,
	uint32_t addr, uint16_t *data,
	enum msm_camera_i2c_data_type data_type);

int32_t msm_camera_spi_read_seq(struct msm_camera_i2c_client *client,
	uint32_t addr, uint8_t *data, uint32_t num_byte);

int32_t msm_camera_spi_read_seq_l(struct msm_camera_i2c_client *client,
	uint32_t addr, uint32_t num_byte, char *tx, char *rx);

int32_t msm_camera_spi_query_id(struct msm_camera_i2c_client *client,
	uint32_t addr, uint8_t *data, uint32_t num_byte);

int32_t msm_camera_spi_write_seq(struct msm_camera_i2c_client *client,
	uint32_t addr, uint8_t *data, uint32_t num_byte);

int32_t msm_camera_spi_erase(struct msm_camera_i2c_client *client,
	uint32_t addr, uint32_t size);

int32_t msm_camera_spi_write(struct msm_camera_i2c_client *client,
	uint32_t addr, uint16_t data, enum msm_camera_i2c_data_type data_type);

int32_t msm_camera_spi_write_table(struct msm_camera_i2c_client *client,
	struct msm_camera_i2c_reg_setting *write_setting);

int32_t msm_camera_spi_write_burst(struct msm_camera_i2c_client *client,
	struct msm_camera_i2c_reg_array *reg_setting, uint32_t reg_size,
	uint32_t buf_len, uint32_t addr,
	enum msm_camera_i2c_data_type data_type);

int32_t msm_camera_spi_read_burst(struct msm_camera_i2c_client *client,
	uint32_t read_byte, uint8_t *buffer, uint32_t addr,
	enum msm_camera_i2c_data_type data_type);

#endif

/* Copyright (c) 2013-2015, The Linux Foundation. All rights reserved.
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

#include "kgsl.h"
#include "kgsl_sharedmem.h"
#include "kgsl_snapshot.h"

#include "adreno.h"
#include "adreno_pm4types.h"
#include "a3xx_reg.h"
#include "adreno_cp_parser.h"

#define MAX_IB_OBJS 1000
#define NUM_SET_DRAW_GROUPS 32

struct set_draw_state {
	uint64_t cmd_stream_addr;
	uint64_t cmd_stream_dwords;
};

struct ib_parser_variables {
	
	unsigned int cp_addr_regs[ADRENO_CP_ADDR_MAX];
	
	struct set_draw_state set_draw_groups[NUM_SET_DRAW_GROUPS];
};

static int load_state_unit_sizes[7][2] = {
	{ 2, 4 },
	{ 0, 1 },
	{ 2, 4 },
	{ 0, 1 },
	{ 8, 2 },
	{ 8, 2 },
	{ 8, 2 },
};

static int adreno_ib_find_objs(struct kgsl_device *device,
				struct kgsl_process_private *process,
				uint64_t gpuaddr, uint64_t dwords,
				int obj_type,
				struct adreno_ib_object_list *ib_obj_list,
				int ib_level);

static int ib_parse_set_draw_state(struct kgsl_device *device,
	unsigned int *ptr,
	struct kgsl_process_private *process,
	struct adreno_ib_object_list *ib_obj_list,
	struct ib_parser_variables *ib_parse_vars);

static int ib_parse_type7_set_draw_state(struct kgsl_device *device,
	unsigned int *ptr,
	struct kgsl_process_private *process,
	struct adreno_ib_object_list *ib_obj_list);

static void adreno_ib_merge_range(struct adreno_ib_object *ib_obj,
		uint64_t gpuaddr, uint64_t size)
{
	uint64_t addr_end1 = ib_obj->gpuaddr + ib_obj->size;
	uint64_t addr_end2 = gpuaddr + size;
	if (gpuaddr < ib_obj->gpuaddr)
		ib_obj->gpuaddr = gpuaddr;
	if (addr_end2 > addr_end1)
		ib_obj->size = addr_end2 - ib_obj->gpuaddr;
	else
		ib_obj->size = addr_end1 - ib_obj->gpuaddr;
}

static struct adreno_ib_object *adreno_ib_check_overlap(uint64_t gpuaddr,
		uint64_t size, int type,
		struct adreno_ib_object_list *ib_obj_list)
{
	struct adreno_ib_object *ib_obj;
	int i;

	for (i = 0; i < ib_obj_list->num_objs; i++) {
		ib_obj = &(ib_obj_list->obj_list[i]);
		if ((type == ib_obj->snapshot_obj_type) &&
			kgsl_addr_range_overlap(ib_obj->gpuaddr, ib_obj->size,
			gpuaddr, size))
			
			return ib_obj;
	}
	return NULL;
}

static int adreno_ib_add_range(struct kgsl_process_private *process,
				uint64_t gpuaddr,
				uint64_t size, int type,
				struct adreno_ib_object_list *ib_obj_list)
{
	struct adreno_ib_object *ib_obj;
	struct kgsl_mem_entry *entry;

	if (MAX_IB_OBJS <= ib_obj_list->num_objs)
		return -E2BIG;

	entry = kgsl_sharedmem_find_region(process, gpuaddr, size);
	if (!entry)
		return 0;

	if (!size) {
		size = entry->memdesc.size;
		gpuaddr = entry->memdesc.gpuaddr;
	}

	ib_obj = adreno_ib_check_overlap(gpuaddr, size, type, ib_obj_list);
	if (ib_obj) {
		adreno_ib_merge_range(ib_obj, gpuaddr, size);
		kgsl_mem_entry_put(entry);
	} else {
		adreno_ib_init_ib_obj(gpuaddr, size, type, entry,
			&(ib_obj_list->obj_list[ib_obj_list->num_objs]));
		ib_obj_list->num_objs++;
	}
	return 0;
}

static int ib_save_mip_addresses(unsigned int *pkt,
		struct kgsl_process_private *process,
		struct adreno_ib_object_list *ib_obj_list)
{
	int ret = 0;
	int num_levels = (pkt[1] >> 22) & 0x03FF;
	int i;
	unsigned int *hostptr;
	struct kgsl_mem_entry *ent;
	unsigned int block, type;
	int unitsize = 0;

	block = (pkt[1] >> 19) & 0x07;
	type = pkt[2] & 0x03;

	if (type == 0)
		unitsize = load_state_unit_sizes[block][0];
	else
		unitsize = load_state_unit_sizes[block][1];

	if (3 == block && 1 == type) {
		ent = kgsl_sharedmem_find_region(process, pkt[2] & 0xFFFFFFFC,
					(num_levels * unitsize) << 2);
		if (!ent)
			return 0;

		hostptr = kgsl_gpuaddr_to_vaddr(&ent->memdesc,
				pkt[2] & 0xFFFFFFFC);
		if (!hostptr) {
			kgsl_mem_entry_put(ent);
			return 0;
		}
		for (i = 0; i < num_levels; i++) {
			ret = adreno_ib_add_range(process, hostptr[i],
				0, SNAPSHOT_GPU_OBJECT_GENERIC, ib_obj_list);
			if (ret)
				break;
		}
		kgsl_memdesc_unmap(&ent->memdesc);
		kgsl_mem_entry_put(ent);
	}
	return ret;
}

static int ib_parse_load_state(unsigned int *pkt,
	struct kgsl_process_private *process,
	struct adreno_ib_object_list *ib_obj_list,
	struct ib_parser_variables *ib_parse_vars)
{
	int ret = 0;
	int i;


	if (type3_pkt_size(pkt[0]) < 2)
		return 0;

	for (i = 0; i <= (type3_pkt_size(pkt[0]) - 2); i++) {
		ret |= adreno_ib_add_range(process, pkt[2 + i] & 0xFFFFFFFC, 0,
				SNAPSHOT_GPU_OBJECT_GENERIC,
				ib_obj_list);
		if (ret)
			break;
	}
	
	if (!ret)
		ret = ib_save_mip_addresses(pkt, process, ib_obj_list);
	return ret;
}


static int ib_parse_set_bin_data(unsigned int *pkt,
	struct kgsl_process_private *process,
	struct adreno_ib_object_list *ib_obj_list,
	struct ib_parser_variables *ib_parse_vars)
{
	int ret = 0;

	if (type3_pkt_size(pkt[0]) < 2)
		return 0;

	
	ret = adreno_ib_add_range(process, pkt[1], 0,
		SNAPSHOT_GPU_OBJECT_GENERIC, ib_obj_list);
	if (ret)
		return ret;

	
	ret = adreno_ib_add_range(process, pkt[2], 0,
		SNAPSHOT_GPU_OBJECT_GENERIC, ib_obj_list);

	return ret;
}

/*
 * This opcode writes to GPU memory - if the buffer is written to, there is a
 * good chance that it would be valuable to capture in the snapshot, so mark all
 * buffers that are written to as frozen
 */

static int ib_parse_mem_write(unsigned int *pkt,
	struct kgsl_process_private *process,
	struct adreno_ib_object_list *ib_obj_list,
	struct ib_parser_variables *ib_parse_vars)
{
	if (type3_pkt_size(pkt[0]) < 1)
		return 0;

	/*
	 * The address is where the data in the rest of this packet is written
	 * to, but since that might be an offset into the larger buffer we need
	 * to get the whole thing. Pass a size of 0 tocapture the entire buffer.
	 */

	return adreno_ib_add_range(process, pkt[1] & 0xFFFFFFFC, 0,
		SNAPSHOT_GPU_OBJECT_GENERIC, ib_obj_list);
}

static int ib_add_type0_entries(struct kgsl_device *device,
	struct kgsl_process_private *process,
	struct adreno_ib_object_list *ib_obj_list,
	struct ib_parser_variables *ib_parse_vars)
{
	struct adreno_device *adreno_dev = ADRENO_DEVICE(device);
	int ret = 0;
	int i;
	int vfd_end;
	unsigned int mask;
	
	if (adreno_is_a4xx(adreno_dev))
		mask = 0xFFFFFFFC;
	else
		mask = 0xFFFFFFFF;
	for (i = ADRENO_CP_ADDR_VSC_PIPE_DATA_ADDRESS_0;
		i < ADRENO_CP_ADDR_VSC_PIPE_DATA_LENGTH_7; i++) {
		if (ib_parse_vars->cp_addr_regs[i]) {
			ret = adreno_ib_add_range(process,
				ib_parse_vars->cp_addr_regs[i] & mask,
				0, SNAPSHOT_GPU_OBJECT_GENERIC,
				ib_obj_list);
			if (ret)
				return ret;
			ib_parse_vars->cp_addr_regs[i] = 0;
			ib_parse_vars->cp_addr_regs[i + 1] = 0;
			i++;
		}
	}

	vfd_end = adreno_is_a4xx(adreno_dev) ?
		ADRENO_CP_ADDR_VFD_FETCH_INSTR_1_31 :
		ADRENO_CP_ADDR_VFD_FETCH_INSTR_1_15;
	for (i = ADRENO_CP_ADDR_VFD_FETCH_INSTR_1_0;
		i <= vfd_end; i++) {
		if (ib_parse_vars->cp_addr_regs[i]) {
			ret = adreno_ib_add_range(process,
				ib_parse_vars->cp_addr_regs[i],
				0, SNAPSHOT_GPU_OBJECT_GENERIC,
				ib_obj_list);
			if (ret)
				return ret;
			ib_parse_vars->cp_addr_regs[i] = 0;
		}
	}

	if (ib_parse_vars->cp_addr_regs[ADRENO_CP_ADDR_VSC_SIZE_ADDRESS]) {
		ret = adreno_ib_add_range(process,
			ib_parse_vars->cp_addr_regs[
				ADRENO_CP_ADDR_VSC_SIZE_ADDRESS] & mask,
			0, SNAPSHOT_GPU_OBJECT_GENERIC, ib_obj_list);
		if (ret)
			return ret;
		ib_parse_vars->cp_addr_regs[
			ADRENO_CP_ADDR_VSC_SIZE_ADDRESS] = 0;
	}
	mask = 0xFFFFFFE0;
	for (i = ADRENO_CP_ADDR_SP_VS_PVT_MEM_ADDR;
		i <= ADRENO_CP_ADDR_SP_FS_OBJ_START_REG; i++) {
		ret = adreno_ib_add_range(process,
			ib_parse_vars->cp_addr_regs[i] & mask,
			0, SNAPSHOT_GPU_OBJECT_GENERIC, ib_obj_list);
		if (ret)
			return ret;
		ib_parse_vars->cp_addr_regs[i] = 0;
	}
	return ret;
}

static int ib_parse_draw_indx(struct kgsl_device *device, unsigned int *pkt,
	struct kgsl_process_private *process,
	struct adreno_ib_object_list *ib_obj_list,
	struct ib_parser_variables *ib_parse_vars)
{
	int ret = 0;
	int i;
	int opcode = cp_type3_opcode(pkt[0]);

	switch (opcode) {
	case CP_DRAW_INDX:
		if (type3_pkt_size(pkt[0]) > 3) {
			ret = adreno_ib_add_range(process,
				pkt[4], 0,
				SNAPSHOT_GPU_OBJECT_GENERIC, ib_obj_list);
		}
		break;
	case CP_DRAW_INDX_OFFSET:
		if (type3_pkt_size(pkt[0]) == 6) {
			ret = adreno_ib_add_range(process,
				pkt[5], 0,
				SNAPSHOT_GPU_OBJECT_GENERIC, ib_obj_list);
		}
		break;
	case CP_DRAW_INDIRECT:
		if (type3_pkt_size(pkt[0]) == 2) {
			ret = adreno_ib_add_range(process,
				pkt[2], 0,
				SNAPSHOT_GPU_OBJECT_GENERIC, ib_obj_list);
		}
		break;
	case CP_DRAW_INDX_INDIRECT:
		if (type3_pkt_size(pkt[0]) == 4) {
			ret = adreno_ib_add_range(process,
				pkt[2], 0,
				SNAPSHOT_GPU_OBJECT_GENERIC, ib_obj_list);
			if (ret)
				break;
			ret = adreno_ib_add_range(process,
				pkt[4], 0,
				SNAPSHOT_GPU_OBJECT_GENERIC, ib_obj_list);
		}
		break;
	case CP_DRAW_AUTO:
		if (type3_pkt_size(pkt[0]) == 6) {
			ret = adreno_ib_add_range(process,
				 pkt[3], 0, SNAPSHOT_GPU_OBJECT_GENERIC,
				ib_obj_list);
			if (ret)
				break;
			ret = adreno_ib_add_range(process,
				pkt[4], 0,
				SNAPSHOT_GPU_OBJECT_GENERIC, ib_obj_list);
		}
		break;
	}

	if (ret)
		return ret;
	ret = ib_add_type0_entries(device, process, ib_obj_list,
				ib_parse_vars);
	if (ret)
		return ret;
	
	for (i = 0; i < NUM_SET_DRAW_GROUPS; i++) {
		if (!ib_parse_vars->set_draw_groups[i].cmd_stream_dwords)
			continue;
		ret = adreno_ib_find_objs(device, process,
			ib_parse_vars->set_draw_groups[i].cmd_stream_addr,
			ib_parse_vars->set_draw_groups[i].cmd_stream_dwords,
			SNAPSHOT_GPU_OBJECT_DRAW,
			ib_obj_list, 2);
		if (ret)
			break;
	}
	return ret;
}


static int ib_parse_type7(struct kgsl_device *device, unsigned int *ptr,
	struct kgsl_process_private *process,
	struct adreno_ib_object_list *ib_obj_list,
	struct ib_parser_variables *ib_parse_vars)
{
	int opcode = cp_type7_opcode(*ptr);

	switch (opcode) {
	case CP_SET_DRAW_STATE:
		return ib_parse_type7_set_draw_state(device, ptr, process,
					ib_obj_list);
	}

	return 0;
}


static int ib_parse_type3(struct kgsl_device *device, unsigned int *ptr,
	struct kgsl_process_private *process,
	struct adreno_ib_object_list *ib_obj_list,
	struct ib_parser_variables *ib_parse_vars)
{
	int opcode = cp_type3_opcode(*ptr);

	switch (opcode) {
	case  CP_LOAD_STATE:
		return ib_parse_load_state(ptr, process, ib_obj_list,
					ib_parse_vars);
	case CP_SET_BIN_DATA:
		return ib_parse_set_bin_data(ptr, process, ib_obj_list,
					ib_parse_vars);
	case CP_MEM_WRITE:
		return ib_parse_mem_write(ptr, process, ib_obj_list,
					ib_parse_vars);
	case CP_DRAW_INDX:
	case CP_DRAW_INDX_OFFSET:
	case CP_DRAW_INDIRECT:
	case CP_DRAW_INDX_INDIRECT:
		return ib_parse_draw_indx(device, ptr, process, ib_obj_list,
					ib_parse_vars);
	case CP_SET_DRAW_STATE:
		return ib_parse_set_draw_state(device, ptr, process,
					ib_obj_list, ib_parse_vars);
	}

	return 0;
}

/*
 * Parse type0 packets found in the stream.  Some of the registers that are
 * written are clues for GPU buffers that we need to freeze.  Register writes
 * are considred valid when a draw initator is called, so just cache the values
 * here and freeze them when a CP_DRAW_INDX is seen.  This protects against
 * needlessly caching buffers that won't be used during a draw call
 */

static int ib_parse_type0(struct kgsl_device *device, unsigned int *ptr,
	struct kgsl_process_private *process,
	struct adreno_ib_object_list *ib_obj_list,
	struct ib_parser_variables *ib_parse_vars)
{
	struct adreno_device *adreno_dev = ADRENO_DEVICE(device);
	int size = type0_pkt_size(*ptr);
	int offset = type0_pkt_offset(*ptr);
	int i;
	int reg_index;
	int ret = 0;

	for (i = 0; i < size; i++, offset++) {
		
		if (offset >= adreno_cp_parser_getreg(adreno_dev,
				ADRENO_CP_ADDR_VSC_PIPE_DATA_ADDRESS_0) &&
			offset <= adreno_cp_parser_getreg(adreno_dev,
				ADRENO_CP_ADDR_VSC_PIPE_DATA_LENGTH_7)) {
			reg_index = adreno_cp_parser_regindex(
					adreno_dev, offset,
					ADRENO_CP_ADDR_VSC_PIPE_DATA_ADDRESS_0,
					ADRENO_CP_ADDR_VSC_PIPE_DATA_LENGTH_7);
			if (reg_index >= 0)
				ib_parse_vars->cp_addr_regs[reg_index] =
								ptr[i + 1];
			continue;
		} else if ((offset >= adreno_cp_parser_getreg(adreno_dev,
					ADRENO_CP_ADDR_VFD_FETCH_INSTR_1_0)) &&
			(offset <= adreno_cp_parser_getreg(adreno_dev,
				ADRENO_CP_ADDR_VFD_FETCH_INSTR_1_15))) {
			reg_index = adreno_cp_parser_regindex(adreno_dev,
					offset,
					ADRENO_CP_ADDR_VFD_FETCH_INSTR_1_0,
					ADRENO_CP_ADDR_VFD_FETCH_INSTR_1_15);
			if (reg_index >= 0)
				ib_parse_vars->cp_addr_regs[reg_index] =
								ptr[i + 1];
			continue;
		} else if ((offset >= adreno_cp_parser_getreg(adreno_dev,
					ADRENO_CP_ADDR_VFD_FETCH_INSTR_1_16)) &&
			(offset <= adreno_cp_parser_getreg(adreno_dev,
				ADRENO_CP_ADDR_VFD_FETCH_INSTR_1_31))) {
			reg_index = adreno_cp_parser_regindex(adreno_dev,
					offset,
					ADRENO_CP_ADDR_VFD_FETCH_INSTR_1_16,
					ADRENO_CP_ADDR_VFD_FETCH_INSTR_1_31);
			if (reg_index >= 0)
				ib_parse_vars->cp_addr_regs[reg_index] =
								ptr[i + 1];
			continue;
		} else {
			if (offset ==
				adreno_cp_parser_getreg(adreno_dev,
					ADRENO_CP_ADDR_VSC_SIZE_ADDRESS))
				ib_parse_vars->cp_addr_regs[
					ADRENO_CP_ADDR_VSC_SIZE_ADDRESS] =
						ptr[i + 1];
			else if (offset == adreno_cp_parser_getreg(adreno_dev,
					ADRENO_CP_ADDR_SP_VS_PVT_MEM_ADDR))
				ib_parse_vars->cp_addr_regs[
					ADRENO_CP_ADDR_SP_VS_PVT_MEM_ADDR] =
						ptr[i + 1];
			else if (offset == adreno_cp_parser_getreg(adreno_dev,
					ADRENO_CP_ADDR_SP_FS_PVT_MEM_ADDR))
				ib_parse_vars->cp_addr_regs[
					ADRENO_CP_ADDR_SP_FS_PVT_MEM_ADDR] =
						ptr[i + 1];
			else if (offset == adreno_cp_parser_getreg(adreno_dev,
					ADRENO_CP_ADDR_SP_VS_OBJ_START_REG))
				ib_parse_vars->cp_addr_regs[
					ADRENO_CP_ADDR_SP_VS_OBJ_START_REG] =
						ptr[i + 1];
			else if (offset == adreno_cp_parser_getreg(adreno_dev,
					ADRENO_CP_ADDR_SP_FS_OBJ_START_REG))
				ib_parse_vars->cp_addr_regs[
					ADRENO_CP_ADDR_SP_FS_OBJ_START_REG] =
						ptr[i + 1];
			else if ((offset == adreno_cp_parser_getreg(adreno_dev,
					ADRENO_CP_UCHE_INVALIDATE0)) ||
				(offset == adreno_cp_parser_getreg(adreno_dev,
					ADRENO_CP_UCHE_INVALIDATE1))) {
					ret = adreno_ib_add_range(process,
						ptr[i + 1] & 0xFFFFFFC0, 0,
						SNAPSHOT_GPU_OBJECT_GENERIC,
						ib_obj_list);
					if (ret)
						break;
			}
		}
	}
	return ret;
}

static int ib_parse_type7_set_draw_state(struct kgsl_device *device,
	unsigned int *ptr,
	struct kgsl_process_private *process,
	struct adreno_ib_object_list *ib_obj_list)
{
	int size = type7_pkt_size(*ptr);
	int i;
	int grp_id;
	int ret = 0;
	int flags;
	uint64_t cmd_stream_dwords;
	uint64_t cmd_stream_addr;

	for (i = 1; i <= size; i += 3) {
		grp_id = (ptr[i] & 0x1F000000) >> 24;
		
		flags = (ptr[i] & 0x000F0000) >> 16;

		if (flags & 0x1 || !flags) {
			cmd_stream_dwords = ptr[i] & 0x0000FFFF;
			cmd_stream_addr = ptr[i + 2];
			cmd_stream_addr = cmd_stream_addr << 32 | ptr[i + 1];
			if (cmd_stream_dwords)
				ret = adreno_ib_find_objs(device, process,
					cmd_stream_addr, cmd_stream_dwords,
					SNAPSHOT_GPU_OBJECT_DRAW, ib_obj_list,
					2);
			if (ret)
				break;
			continue;
		}
		
		if (flags & 0x8) {
			uint64_t gpuaddr = ptr[i + 2];
			gpuaddr = gpuaddr << 32 | ptr[i + 1];
			ret = adreno_ib_find_objs(device, process,
				gpuaddr, (ptr[i] & 0x0000FFFF),
				SNAPSHOT_GPU_OBJECT_IB,
				ib_obj_list, 2);
			if (ret)
				break;
		}
	}
	return ret;
}

static int ib_parse_set_draw_state(struct kgsl_device *device,
	unsigned int *ptr,
	struct kgsl_process_private *process,
	struct adreno_ib_object_list *ib_obj_list,
	struct ib_parser_variables *ib_parse_vars)
{
	int size = type0_pkt_size(*ptr);
	int i;
	int grp_id;
	int ret = 0;
	int flags;

	for (i = 1; i <= size; i += 2) {
		grp_id = (ptr[i] & 0x1F000000) >> 24;
		
		flags = (ptr[i] & 0x000F0000) >> 16;
		
		if (flags & 0x4) {
			int j;
			for (j = 0; j < NUM_SET_DRAW_GROUPS; j++)
				ib_parse_vars->set_draw_groups[j].
					cmd_stream_dwords = 0;
			continue;
		}
		
		if (flags & 0x2) {
			ib_parse_vars->set_draw_groups[grp_id].
						cmd_stream_dwords = 0;
			continue;
		}
		if (flags & 0x1 || !flags) {
			ib_parse_vars->set_draw_groups[grp_id].
				cmd_stream_dwords = ptr[i] & 0x0000FFFF;
			ib_parse_vars->set_draw_groups[grp_id].
				cmd_stream_addr = ptr[i + 1];
			continue;
		}
		
		if (flags & 0x8) {
			ret = adreno_ib_find_objs(device, process,
				ptr[i + 1], (ptr[i] & 0x0000FFFF),
				SNAPSHOT_GPU_OBJECT_IB,
				ib_obj_list, 2);
			if (ret)
				break;
		}
	}
	return ret;
}

static int adreno_cp_parse_ib2(struct kgsl_device *device,
			struct kgsl_process_private *process,
			uint64_t gpuaddr, uint64_t dwords,
			struct adreno_ib_object_list *ib_obj_list,
			int ib_level)
{
	struct adreno_ib_object *ib_obj = NULL;
	int i;
	if (2 == ib_level)
		return -EINVAL;
	for (i = 0; i < ib_obj_list->num_objs; i++) {
		ib_obj = &(ib_obj_list->obj_list[i]);
		if ((ib_obj != NULL) &&
			(SNAPSHOT_GPU_OBJECT_IB == ib_obj->snapshot_obj_type) &&
			(gpuaddr >= ib_obj->gpuaddr) &&
			(gpuaddr + dwords * sizeof(unsigned int) <=
			ib_obj->gpuaddr + ib_obj->size))
			return 0;
	}

	return adreno_ib_find_objs(device, process, gpuaddr, dwords,
		SNAPSHOT_GPU_OBJECT_IB, ib_obj_list, 2);
}

static int adreno_ib_find_objs(struct kgsl_device *device,
				struct kgsl_process_private *process,
				uint64_t gpuaddr, uint64_t dwords,
				int obj_type,
				struct adreno_ib_object_list *ib_obj_list,
				int ib_level)
{
	int ret = 0;
	uint64_t rem = dwords;
	int i;
	struct ib_parser_variables ib_parse_vars;
	unsigned int *src;
	struct adreno_ib_object *ib_obj;
	struct kgsl_mem_entry *entry;
	struct adreno_device *adreno_dev = ADRENO_DEVICE(device);

	
	for (i = 0; i < ib_obj_list->num_objs; i++) {
		ib_obj = &(ib_obj_list->obj_list[i]);
		if ((obj_type == ib_obj->snapshot_obj_type) &&
			(ib_obj->gpuaddr <= gpuaddr) &&
			((ib_obj->gpuaddr + ib_obj->size) >=
			(gpuaddr + (dwords << 2))))
			return 0;
	}

	entry = kgsl_sharedmem_find_region(process, gpuaddr,
					(dwords << 2));
	if (!entry)
		return -EINVAL;

	src = kgsl_gpuaddr_to_vaddr(&entry->memdesc, gpuaddr);
	if (!src) {
		kgsl_mem_entry_put(entry);
		return -EINVAL;
	}

	memset(&ib_parse_vars, 0, sizeof(struct ib_parser_variables));

	ret = adreno_ib_add_range(process, gpuaddr, dwords << 2,
				obj_type, ib_obj_list);
	if (ret)
		goto done;

	for (i = 0; rem > 0; rem--, i++) {
		int pktsize;

		if (pkt_is_type0(src[i]))
			pktsize = type0_pkt_size(src[i]);

		else if (pkt_is_type3(src[i]))
			pktsize = type3_pkt_size(src[i]);

		else if (pkt_is_type4(src[i]))
			pktsize = type4_pkt_size(src[i]);

		else if (pkt_is_type7(src[i]))
			pktsize = type7_pkt_size(src[i]);

		else
			break;

		if (((pkt_is_type0(src[i]) || pkt_is_type3(src[i])) && !pktsize)
			|| ((pktsize + 1) > rem))
			break;

		if (pkt_is_type3(src[i])) {
			if (adreno_cmd_is_ib(adreno_dev, src[i])) {
				uint64_t gpuaddrib2 = src[i + 1];
				uint64_t size = src[i + 2];

				ret = adreno_cp_parse_ib2(device, process,
						gpuaddrib2, size,
						ib_obj_list, ib_level);
				if (ret)
					goto done;
			} else {
				ret = ib_parse_type3(device, &src[i], process,
						ib_obj_list,
						&ib_parse_vars);

				if (ret)
					goto done;
			}
		}

		else if (pkt_is_type7(src[i])) {
			if (adreno_cmd_is_ib(adreno_dev, src[i])) {
				uint64_t size = src[i + 3];
				uint64_t gpuaddrib2 = src[i + 2];
				gpuaddrib2 = gpuaddrib2 << 32 | src[i + 1];

				ret = adreno_cp_parse_ib2(device, process,
						gpuaddrib2, size,
						ib_obj_list, ib_level);
				if (ret)
					goto done;
			} else {
				ret = ib_parse_type7(device, &src[i], process,
						ib_obj_list,
						&ib_parse_vars);

				if (ret)
					goto done;
			}
		}

		else if (pkt_is_type0(src[i])) {
			ret = ib_parse_type0(device, &src[i], process,
					ib_obj_list, &ib_parse_vars);
			if (ret)
				goto done;
		}

		i += pktsize;
		rem -= pktsize;
	}

done:
	if (!ret && SNAPSHOT_GPU_OBJECT_DRAW == obj_type)
		ret = ib_add_type0_entries(device, process, ib_obj_list,
			&ib_parse_vars);

	kgsl_memdesc_unmap(&entry->memdesc);
	kgsl_mem_entry_put(entry);
	return ret;
}


int adreno_ib_create_object_list(struct kgsl_device *device,
		struct kgsl_process_private *process,
		uint64_t gpuaddr, uint64_t dwords,
		struct adreno_ib_object_list **out_ib_obj_list)
{
	int ret = 0;
	struct adreno_ib_object_list *ib_obj_list;

	if (!out_ib_obj_list)
		return -EINVAL;

	*out_ib_obj_list = NULL;

	ib_obj_list = kzalloc(sizeof(*ib_obj_list), GFP_KERNEL);
	if (!ib_obj_list)
		return -ENOMEM;

	ib_obj_list->obj_list = vmalloc(MAX_IB_OBJS *
					sizeof(struct adreno_ib_object));

	if (!ib_obj_list->obj_list) {
		kfree(ib_obj_list);
		return -ENOMEM;
	}

	ret = adreno_ib_find_objs(device, process, gpuaddr, dwords,
		SNAPSHOT_GPU_OBJECT_IB, ib_obj_list, 1);

	
	if (ib_obj_list->num_objs)
		*out_ib_obj_list = ib_obj_list;

	return ret;
}

void adreno_ib_destroy_obj_list(struct adreno_ib_object_list *ib_obj_list)
{
	int i;

	if (!ib_obj_list)
		return;

	for (i = 0; i < ib_obj_list->num_objs; i++) {
		if (ib_obj_list->obj_list[i].entry)
			kgsl_mem_entry_put(ib_obj_list->obj_list[i].entry);
	}
	vfree(ib_obj_list->obj_list);
	kfree(ib_obj_list);
}

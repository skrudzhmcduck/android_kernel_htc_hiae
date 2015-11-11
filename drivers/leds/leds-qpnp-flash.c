/* Copyright (c) 2014-2015, The Linux Foundation. All rights reserved.
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

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/leds.h>
#include <linux/slab.h>
#include <linux/of_device.h>
#include <linux/spmi.h>
#include <linux/err.h>
#include <linux/delay.h>
#include <linux/of.h>
#include <linux/regulator/consumer.h>
#include <linux/workqueue.h>
#include <linux/power_supply.h>
#include <linux/qpnp/qpnp-adc.h>
#include "leds.h"
#include <linux/debugfs.h>
#include <linux/uaccess.h>
#include <linux/htc_flashlight.h>
#include <linux/of_gpio.h>

#define FLT_DBG_LOG(fmt, ...) \
		printk(KERN_DEBUG "[FLT][DBG] " fmt, ##__VA_ARGS__)
#define FLT_INFO_LOG(fmt, ...) \
		printk(KERN_INFO "[FLT] " fmt, ##__VA_ARGS__)
#define FLT_ERR_LOG(fmt, ...) \
		printk(KERN_ERR "[FLT][ERR] " fmt, ##__VA_ARGS__)

#define FLASH_LED_PERIPHERAL_SUBTYPE(base)			(base + 0x05)
#define FLASH_SAFETY_TIMER(base)				(base + 0x40)
#define FLASH_MAX_CURRENT(base)					(base + 0x41)
#define FLASH_LED0_CURRENT(base)				(base + 0x42)
#define FLASH_LED1_CURRENT(base)				(base + 0x43)
#define	FLASH_CLAMP_CURRENT(base)				(base + 0x44)
#define FLASH_MODULE_ENABLE_CTRL(base)				(base + 0x46)
#define	FLASH_LED_STROBE_CTRL(base)				(base + 0x47)
#define FLASH_LED_TMR_CTRL(base)				(base + 0x48)
#define FLASH_HEADROOM(base)					(base + 0x4A)
#define	FLASH_STARTUP_DELAY(base)				(base + 0x4B)
#define FLASH_MASK_ENABLE(base)					(base + 0x4C)
#define FLASH_VREG_OK_FORCE(base)				(base + 0x4F)
#define FLASH_FAULT_DETECT(base)				(base + 0x51)
#define	FLASH_THERMAL_DRATE(base)				(base + 0x52)
#define	FLASH_CURRENT_RAMP(base)				(base + 0x54)
#define	FLASH_VPH_PWR_DROOP(base)				(base + 0x5A)
#define	FLASH_HDRM_SNS_ENABLE_CTRL0(base)			(base + 0x5C)
#define	FLASH_HDRM_SNS_ENABLE_CTRL1(base)			(base + 0x5D)
#define	FLASH_LED_UNLOCK_SECURE(base)				(base + 0xD0)
#define FLASH_PERPH_RESET_CTRL(base)				(base + 0xDA)
#define	FLASH_TORCH(base)					(base + 0xE4)

#define FLASH_STATUS_REG_MASK					0xFF
#define FLASH_LED_FAULT_STATUS(base)				(base + 0x08)
#define INT_LATCHED_STS(base)					(base + 0x18)
#define IN_POLARITY_HIGH(base)					(base + 0x12)
#define INT_SET_TYPE(base)					(base + 0x11)
#define INT_EN_SET(base)					(base + 0x15)
#define INT_LATCHED_CLR(base)					(base + 0x14)

#define	FLASH_HEADROOM_MASK					0x03
#define FLASH_STARTUP_DLY_MASK					0x03
#define	FLASH_VREG_OK_FORCE_MASK				0xC0
#define	FLASH_FAULT_DETECT_MASK					0x80
#define	FLASH_THERMAL_DERATE_MASK				0xBF
#define FLASH_SECURE_MASK					0xFF
#define FLASH_TORCH_MASK					0x03
#define FLASH_CURRENT_MASK					0x7F
#define FLASH_TMR_MASK						0x03
#define FLASH_TMR_SAFETY					0x00
#define FLASH_SAFETY_TIMER_MASK					0x7F
#define FLASH_MODULE_ENABLE_MASK				0xE0
#define FLASH_STROBE_MASK					0xC0
#define FLASH_CURRENT_RAMP_MASK					0xBF
#define FLASH_VPH_PWR_DROOP_MASK				0xF3
#define FLASH_LED_HDRM_SNS_ENABLE_MASK				0x81
#define	FLASH_MASK_MODULE_CONTRL_MASK				0xE0
#define FLASH_FOLLOW_OTST2_RB_MASK				0x08

#define FLASH_LED_TRIGGER_DEFAULT				"none"
#define FLASH_LED_HEADROOM_DEFAULT_MV				500
#define FLASH_LED_STARTUP_DELAY_DEFAULT_US			128
#define FLASH_LED_CLAMP_CURRENT_DEFAULT_MA			200
#define	FLASH_LED_THERMAL_DERATE_THRESHOLD_DEFAULT_C		80
#define	FLASH_LED_RAMP_UP_STEP_DEFAULT_US			3
#define	FLASH_LED_RAMP_DN_STEP_DEFAULT_US			3
#define	FLASH_LED_VPH_PWR_DROOP_THRESHOLD_DEFAULT_MV		3200
#define	FLASH_LED_VPH_PWR_DROOP_DEBOUNCE_TIME_DEFAULT_US	10
#define FLASH_LED_THERMAL_DERATE_RATE_DEFAULT_PERCENT		2
#define FLASH_RAMP_UP_DELAY_US					1000
#define FLASH_RAMP_DN_DELAY_US					2160
#define FLASH_BOOST_REGULATOR_PROBE_DELAY_MS			2000
#define	FLASH_TORCH_MAX_LEVEL					0x0F
#define	FLASH_MAX_LEVEL						0x4F
#define	FLASH_LED_FLASH_HW_VREG_OK				0x40
#define	FLASH_LED_FLASH_SW_VREG_OK				0x80
#define FLASH_LED_STROBE_TYPE_HW				0x40
#define	FLASH_DURATION_DIVIDER					10
#define	FLASH_LED_HEADROOM_DIVIDER				100
#define	FLASH_LED_HEADROOM_OFFSET				2
#define	FLASH_LED_MAX_CURRENT_MA				1000
#define	FLASH_LED_THERMAL_THRESHOLD_MIN				95
#define	FLASH_LED_THERMAL_DEVIDER				10
#define	FLASH_LED_VPH_DROOP_THRESHOLD_MIN_MV			2500
#define	FLASH_LED_VPH_DROOP_THRESHOLD_DIVIDER			100
#define	FLASH_LED_HDRM_SNS_ENABLE				0x81
#define	FLASH_LED_HDRM_SNS_DISABLE				0x01
#define	FLASH_LED_UA_PER_MA					1000
#define	FLASH_LED_MASK_MODULE_MASK2_ENABLE			0x20
#define	FLASH_LED_MASK3_ENABLE_SHIFT				7
#define	FLASH_LED_MODULE_CTRL_DEFAULT				0x60
#define	FLASH_LED_CURRENT_READING_DELAY_MIN			5000
#define	FLASH_LED_CURRENT_READING_DELAY_MAX			5001

#define FLASH_UNLOCK_SECURE					0xA5
#define FLASH_LED_TORCH_ENABLE					0x00
#define FLASH_LED_TORCH_DISABLE					0x03
#define FLASH_MODULE_ENABLE					0x80
#define FLASH_LED0_TRIGGER					0x80
#define FLASH_LED1_TRIGGER					0x40
#define FLASH_LED0_ENABLEMENT					0x40
#define FLASH_LED1_ENABLEMENT					0x20
#define FLASH_LED_DISABLE					0x00
#define	FLASH_LED_MIN_CURRENT_MA				13
#define FLASH_SUBTYPE_DUAL					0x01
#define FLASH_SUBTYPE_SINGLE					0x02
#define FLASH_TIME_OUT						600
#define FLASH_LED_MAX_FLASH_CURRENT_MA		750
#define FLASH_LED_MAX_TORCH_CURRENT_MA		200
#define FLASH_LED_MAX_FLASH_LEVEL(curr)		((curr*2-1)/25)

#define BACKLIGHT_ON						1
#define BACKLIGHT_OFF						0

enum flash_led_id {
	FLASH_LED_0 = 0,
	FLASH_LED_1,
	FLASH_LED_SWITCH,
	FLASH_LED_2,
};

enum flash_led_type {
	FLASH = 0,
	TORCH,
	SWITCH,
	DUAL_LEDS,
};

enum thermal_derate_rate {
	RATE_1_PERCENT = 0,
	RATE_1P25_PERCENT,
	RATE_2_PERCENT,
	RATE_2P5_PERCENT,
	RATE_5_PERCENT,
};

enum current_ramp_steps {
	RAMP_STEP_0P2_US = 0,
	RAMP_STEP_0P4_US,
	RAMP_STEP_0P8_US,
	RAMP_STEP_1P6_US,
	RAMP_STEP_3P3_US,
	RAMP_STEP_6P7_US,
	RAMP_STEP_13P5_US,
	RAMP_STEP_27US,
};


enum flashlight_brightness_attribute_definition
{ 
    FBAD_OFF        = 0,
    FBAD_TORCH1     = 125, 
    FBAD_TORCH2     = 126, 
    FBAD_TORCH      = 127, 
    FBAD_PREFLASH   = 128, 
    FBAD_FULL       = 255, 
};

struct flash_node_data {
	struct spmi_device		*spmi_dev;
	struct led_classdev		cdev;
	struct regulator		*boost_regulator;
	struct work_struct		work;
	struct delayed_work		dwork;
	u32				boost_voltage_max;
	u16				max_current;
	u16				prgm_current;
	u16				prgm_current2;
	u16				duration;
	u8				id;
	u8				type;
	u8				trigger;
	u8				enable;
	bool				flash_on;
};

struct flash_led_platform_data {
	unsigned int			temp_threshold_num;
	unsigned int			temp_derate_curr_num;
	unsigned int			*die_temp_derate_curr_ma;
	unsigned int			*die_temp_threshold_degc;
	u16				ramp_up_step;
	u16				ramp_dn_step;
	u16				vph_pwr_droop_threshold;
	u16				headroom;
	u16				clamp_current;
	u8				thermal_derate_threshold;
	u8				vph_pwr_droop_debounce_time;
	u8				startup_dly;
	u8				thermal_derate_rate;
	bool				pmic_charger_support;
	bool				self_check_en;
	bool				thermal_derate_en;
	bool				current_ramp_en;
	bool				vph_pwr_droop_en;
	bool				hdrm_sns_ch0_en;
	bool				hdrm_sns_ch1_en;
	bool				power_detect_en;
	bool				mask3_en;
	bool				follow_rb_disable;
	bool				die_current_derate_en;
};

struct qpnp_flash_led_buffer {
	size_t rpos;
	size_t wpos;
	size_t len;
	char data[0];
};

struct qpnp_flash_led {
	struct spmi_device		*spmi_dev;
	struct flash_led_platform_data	*pdata;
	struct pinctrl			*pinctrl;
	struct pinctrl_state		*gpio_state_active;
	struct pinctrl_state		*gpio_state_suspend;
	struct flash_node_data		*flash_node;
	struct power_supply		*battery_psy;
	struct workqueue_struct		*ordered_workq;
	struct qpnp_vadc_chip		*vadc_dev;
	struct mutex			flash_led_lock;
	struct qpnp_flash_led_buffer	*log;
	struct dentry			*dbgfs_root;
	int				num_leds;
	u32				buffer_cnt;
	u16				base;
	u16				current_addr;
	u16				current2_addr;
	u8				peripheral_type;
	u8				fault_reg;
	bool				gpio_enabled;
	bool				charging_enabled;
	bool				strobe_debug;
	bool				dbg_feature_en;
};

static u8 qpnp_flash_led_ctrl_dbg_regs[] = {
	0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
	0x4A, 0x4B, 0x4C, 0x4F, 0x51, 0x52, 0x54, 0x55, 0x5A
};

static struct qpnp_flash_led *this_led;

void (*set_backlight)(int on);

struct delayed_work pmi8950_delayed_work;
static struct workqueue_struct *pmi8950_work_queue;
static int flashlight_turn_off(void);

int pmi8950_flash_mode(int, int);
int pmi8950_torch_mode(int, int);

int (*htc_flash_main)(int led1, int led2);
int (*htc_torch_main)(int led1, int led2);

void backlight_callback_register( void (*enable_backlight)(int) )
{
	FLT_INFO_LOG("%s: ++\n", __func__);
	set_backlight = enable_backlight;
}
EXPORT_SYMBOL(backlight_callback_register);

static int flash_led_dbgfs_file_open(struct qpnp_flash_led *led,
					struct file *file)
{
	struct qpnp_flash_led_buffer *log;
	size_t logbufsize = SZ_4K;

	log = kzalloc(logbufsize, GFP_KERNEL);
	if (!log)
		return -ENOMEM;

	log->rpos = 0;
	log->wpos = 0;
	log->len = logbufsize - sizeof(*log);
	led->log = log;

	led->buffer_cnt = 1;
	file->private_data = led;

	return 0;
}

static int flash_led_dfs_open(struct inode *inode, struct file *file)
{
	struct qpnp_flash_led *led = inode->i_private;
	return flash_led_dbgfs_file_open(led, file);
}

static int flash_led_dfs_close(struct inode *inode, struct file *file)
{
	struct qpnp_flash_led *led = file->private_data;

	if (led && led->log) {
		file->private_data = NULL;
		kfree(led->log);
	}

	return 0;
}

static int print_to_log(struct qpnp_flash_led_buffer *log,
					const char *fmt, ...)
{
	va_list args;
	int cnt;
	char *log_buf = &log->data[log->wpos];
	size_t size = log->len - log->wpos;

	va_start(args, fmt);
	cnt = vscnprintf(log_buf, size, fmt, args);
	va_end(args);

	log->wpos += cnt;
	return cnt;
}

static ssize_t flash_led_dfs_latched_reg_read(struct file *fp, char __user *buf,
					size_t count, loff_t *ppos) {
	struct qpnp_flash_led *led = fp->private_data;
	struct qpnp_flash_led_buffer *log = led->log;
	u8 val;
	int rc;
	size_t len;
	size_t ret;

	if (log->rpos >= log->wpos && led->buffer_cnt == 0)
		return 0;

	rc = spmi_ext_register_readl(led->spmi_dev->ctrl,
		led->spmi_dev->sid, INT_LATCHED_STS(led->base), &val, 1);
	if (rc) {
		dev_err(&led->spmi_dev->dev,
				"Unable to read from address %x, rc(%d)\n",
				INT_LATCHED_STS(led->base), rc);
		return -EINVAL;
	}
	led->buffer_cnt--;

	rc = print_to_log(log, "0x%05X ", INT_LATCHED_STS(led->base));
	if (rc == 0)
		return rc;

	rc = print_to_log(log, "0x%02X ", val);
	if (rc == 0)
		return rc;

	if (log->wpos > 0 && log->data[log->wpos - 1] == ' ')
		log->data[log->wpos - 1] = '\n';

	len = min(count, log->wpos - log->rpos);

	ret = copy_to_user(buf, &log->data[log->rpos], len);
	if (ret) {
		pr_err("error copy register value to user\n");
		return -EFAULT;
	}

	len -= ret;
	*ppos += len;
	log->rpos += len;

	return len;
}

static ssize_t flash_led_dfs_fault_reg_read(struct file *fp, char __user *buf,
					size_t count, loff_t *ppos) {
	struct qpnp_flash_led *led = fp->private_data;
	struct qpnp_flash_led_buffer *log = led->log;
	int rc;
	size_t len;
	size_t ret;

	if (log->rpos >= log->wpos && led->buffer_cnt == 0)
		return 0;

	led->buffer_cnt--;

	rc = print_to_log(log, "0x%05X ", FLASH_LED_FAULT_STATUS(led->base));
	if (rc == 0)
		return rc;

	rc = print_to_log(log, "0x%02X ", led->fault_reg);
	if (rc == 0)
		return rc;

	if (log->wpos > 0 && log->data[log->wpos - 1] == ' ')
		log->data[log->wpos - 1] = '\n';

	len = min(count, log->wpos - log->rpos);

	ret = copy_to_user(buf, &log->data[log->rpos], len);
	if (ret) {
		pr_err("error copy register value to user\n");
		return -EFAULT;
	}

	len -= ret;
	*ppos += len;
	log->rpos += len;

	return len;
}

static ssize_t flash_led_dfs_fault_reg_enable(struct file *file,
			const char __user *buf, size_t count, loff_t *ppos) {

	u8 *val;
	int pos = 0;
	int cnt = 0;
	int data;
	size_t ret = 0;

	struct qpnp_flash_led *led = file->private_data;
	char *kbuf = kmalloc(count + 1, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	ret = copy_from_user(kbuf, buf, count);
	if (!ret) {
		pr_err("failed to copy data from user\n");
		ret = -EFAULT;
		goto free_buf;
	}

	count -= ret;
	*ppos += count;
	kbuf[count] = '\0';
	val = kbuf;
	while (sscanf(kbuf + pos, "%i", &data) == 1) {
		pos++;
		val[cnt++] = data & 0xff;
	}

	if (!cnt)
		goto free_buf;

	ret = count;
	if (*val == 1)
		led->strobe_debug = true;
	else
		led->strobe_debug = false;

free_buf:
	kfree(kbuf);
	return ret;
}

static ssize_t flash_led_dfs_dbg_enable(struct file *file,
			const char __user *buf, size_t count, loff_t *ppos) {

	u8 *val;
	int pos = 0;
	int cnt = 0;
	int data;
	size_t ret = 0;

	struct qpnp_flash_led *led = file->private_data;
	char *kbuf = kmalloc(count + 1, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	ret = copy_from_user(kbuf, buf, count);
	if (ret == count) {
		pr_err("failed to copy data from user\n");
		ret = -EFAULT;
		goto free_buf;
	}
	count -= ret;
	*ppos += count;
	kbuf[count] = '\0';
	val = kbuf;
	while (sscanf(kbuf + pos, "%i", &data) == 1) {
		pos++;
		val[cnt++] = data & 0xff;
	}

	if (!cnt)
		goto free_buf;

	ret = count;
	if (*val == 1)
		led->dbg_feature_en = true;
	else
		led->dbg_feature_en = false;

free_buf:
	kfree(kbuf);
	return ret;
}

static const struct file_operations flash_led_dfs_latched_reg_fops = {
	.open		= flash_led_dfs_open,
	.release	= flash_led_dfs_close,
	.read		= flash_led_dfs_latched_reg_read,
};

static const struct file_operations flash_led_dfs_strobe_reg_fops = {
	.open		= flash_led_dfs_open,
	.release	= flash_led_dfs_close,
	.read		= flash_led_dfs_fault_reg_read,
	.write		= flash_led_dfs_fault_reg_enable,
};

static const struct file_operations flash_led_dfs_dbg_feature_fops = {
	.open		= flash_led_dfs_open,
	.release	= flash_led_dfs_close,
	.write		= flash_led_dfs_dbg_enable,
};

static int
qpnp_led_masked_write(struct spmi_device *spmi_dev, u16 addr, u8 mask, u8 val)
{
	int rc;
	u8 reg;

	rc = spmi_ext_register_readl(spmi_dev->ctrl, spmi_dev->sid,
					addr, &reg, 1);
	if (rc)
		dev_err(&spmi_dev->dev,
			"Unable to read from addr=%x, rc(%d)\n", addr, rc);

	reg &= ~mask;
	reg |= val;

	rc = spmi_ext_register_writel(spmi_dev->ctrl, spmi_dev->sid,
					addr, &reg, 1);
	if (rc)
		dev_err(&spmi_dev->dev,
			"Unable to write to addr=%x, rc(%d)\n", addr, rc);

	dev_dbg(&spmi_dev->dev, "Write 0x%02X to addr 0x%02X\n", val, addr);

	return rc;
}

static int qpnp_flash_led_get_allowed_die_temp_curr(struct qpnp_flash_led *led,
							int64_t die_temp_degc)
{
	int die_temp_curr_ma;

	if (die_temp_degc >= led->pdata->die_temp_threshold_degc[0])
		die_temp_curr_ma =  0;
	else if (die_temp_degc >= led->pdata->die_temp_threshold_degc[1])
		die_temp_curr_ma = led->pdata->die_temp_derate_curr_ma[0];
	else if (die_temp_degc >= led->pdata->die_temp_threshold_degc[2])
		die_temp_curr_ma = led->pdata->die_temp_derate_curr_ma[1];
	else if (die_temp_degc >= led->pdata->die_temp_threshold_degc[3])
		die_temp_curr_ma = led->pdata->die_temp_derate_curr_ma[2];
	else if (die_temp_degc >= led->pdata->die_temp_threshold_degc[4])
		die_temp_curr_ma = led->pdata->die_temp_derate_curr_ma[3];
	else
		die_temp_curr_ma = led->pdata->die_temp_derate_curr_ma[4];

	return die_temp_curr_ma;
}

static int64_t qpnp_flash_led_get_die_temp(struct qpnp_flash_led *led)
{
	struct qpnp_vadc_result die_temp_result;
	int rc;

	rc = qpnp_vadc_read(led->vadc_dev, SPARE2, &die_temp_result);
	if (rc) {
		pr_err("failed to read the die temp\n");
		return -EINVAL;
	}

	return die_temp_result.physical;
}

static int
qpnp_flash_led_get_max_avail_current(struct flash_node_data *flash_node,
					struct qpnp_flash_led *led)
{
	union power_supply_propval prop;
	int64_t chg_temp_milidegc, die_temp_degc;
	int max_curr_avail_ma = 2000;
	int allowed_die_temp_curr_ma = 2000;
	int rc;

	if (led->pdata->power_detect_en) {
		if (!led->battery_psy) {
			dev_err(&led->spmi_dev->dev,
				"Failed to query power supply\n");
			return -EINVAL;
		}

		if (led->charging_enabled) {
			rc = qpnp_led_masked_write(led->spmi_dev,
				FLASH_MODULE_ENABLE_CTRL(led->base),
				FLASH_MODULE_ENABLE, FLASH_MODULE_ENABLE);
			if (rc) {
				dev_err(&led->spmi_dev->dev,
				"Module enable reg write failed\n");
				return -EINVAL;
			}

			usleep_range(FLASH_LED_CURRENT_READING_DELAY_MIN,
				FLASH_LED_CURRENT_READING_DELAY_MAX);
		}

		led->battery_psy->get_property(led->battery_psy,
				POWER_SUPPLY_PROP_FLASH_CURRENT_MAX, &prop);
		if (!prop.intval) {
			dev_err(&led->spmi_dev->dev,
				"battery too low for flash\n");
			return -EINVAL;
		}

		max_curr_avail_ma = (prop.intval / FLASH_LED_UA_PER_MA);
	}

	if (led->pdata->die_current_derate_en) {
		chg_temp_milidegc = qpnp_flash_led_get_die_temp(led);
		if (chg_temp_milidegc < 0)
			return -EINVAL;

		die_temp_degc = div_s64(chg_temp_milidegc, 1000);
		allowed_die_temp_curr_ma =
			qpnp_flash_led_get_allowed_die_temp_curr(led,
								die_temp_degc);
		if (allowed_die_temp_curr_ma < 0)
			return -EINVAL;
	}

	max_curr_avail_ma = (max_curr_avail_ma >= allowed_die_temp_curr_ma)
				? allowed_die_temp_curr_ma : max_curr_avail_ma;

	return max_curr_avail_ma;
}

static ssize_t qpnp_flash_led_die_temp_store(struct device *dev,
					struct device_attribute *attr,
					const char *buf, size_t count)
{
	struct qpnp_flash_led *led;
	struct flash_node_data *flash_node;
	unsigned long val;
	struct led_classdev *led_cdev = dev_get_drvdata(dev);
	ssize_t ret;

	ret = kstrtoul(buf, 10, &val);
	if (ret)
		return ret;

	flash_node = container_of(led_cdev, struct flash_node_data, cdev);
	led = dev_get_drvdata(&flash_node->spmi_dev->dev);

	
	if (val == 0)
		led->pdata->die_current_derate_en = false;
	else
		led->pdata->die_current_derate_en = true;

	return count;
}

static ssize_t qpnp_led_strobe_type_store(struct device *dev,
			struct device_attribute *attr,
			const char *buf, size_t count)
{
	struct flash_node_data *flash_node;
	unsigned long state;
	struct led_classdev *led_cdev = dev_get_drvdata(dev);
	ssize_t ret = -EINVAL;

	ret = kstrtoul(buf, 10, &state);
	if (ret)
		return ret;

	flash_node = container_of(led_cdev, struct flash_node_data, cdev);

	
	if (state == 1)
		flash_node->trigger |= FLASH_LED_STROBE_TYPE_HW;
	else
		flash_node->trigger &= ~FLASH_LED_STROBE_TYPE_HW;

	return count;
}

static ssize_t qpnp_flash_led_dump_regs_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct qpnp_flash_led *led;
	struct flash_node_data *flash_node;
	struct led_classdev *led_cdev = dev_get_drvdata(dev);
	int rc, i, count = 0;
	u16 addr;
	u8 val;

	flash_node = container_of(led_cdev, struct flash_node_data, cdev);
	led = dev_get_drvdata(&flash_node->spmi_dev->dev);
	for (i = 0; i < ARRAY_SIZE(qpnp_flash_led_ctrl_dbg_regs); i++) {
		addr = led->base + qpnp_flash_led_ctrl_dbg_regs[i];
		rc = spmi_ext_register_readl(led->spmi_dev->ctrl,
			led->spmi_dev->sid, addr, &val, 1);
		if (rc) {
			dev_err(&led->spmi_dev->dev,
				"Unable to read from addr=%x, rc(%d)\n",
				addr, rc);
			return -EINVAL;
		}

		count += snprintf(buf + count, PAGE_SIZE - count,
				"REG_0x%x = 0x%x\n", addr, val);

		if (count >= PAGE_SIZE)
			return PAGE_SIZE - 1;
	}

	return count;
}

static ssize_t qpnp_flash_led_current_derate_store(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
	struct qpnp_flash_led *led;
	struct flash_node_data *flash_node;
	unsigned long val;
	struct led_classdev *led_cdev = dev_get_drvdata(dev);
	ssize_t ret;

	ret = kstrtoul(buf, 10, &val);
	if (ret)
		return ret;

	flash_node = container_of(led_cdev, struct flash_node_data, cdev);
	led = dev_get_drvdata(&flash_node->spmi_dev->dev);

	
	if (val == 0)
		led->pdata->power_detect_en = false;
	else
		led->pdata->power_detect_en = true;

	return count;
}

static ssize_t qpnp_flash_led_max_current_show(struct device *dev,
			struct device_attribute *attr, char *buf)
{
	struct qpnp_flash_led *led;
	struct flash_node_data *flash_node;
	struct led_classdev *led_cdev = dev_get_drvdata(dev);
	int max_curr_avail_ma = 0;

	flash_node = container_of(led_cdev, struct flash_node_data, cdev);
	led = dev_get_drvdata(&flash_node->spmi_dev->dev);

	if (led->flash_node[0].flash_on)
		max_curr_avail_ma += led->flash_node[0].max_current;
	if (led->flash_node[1].flash_on)
		max_curr_avail_ma += led->flash_node[1].max_current;

	if (led->pdata->power_detect_en ||
			led->pdata->die_current_derate_en) {
		max_curr_avail_ma =
			qpnp_flash_led_get_max_avail_current(flash_node, led);

		if (max_curr_avail_ma < 0)
			return -EINVAL;
	}

	return snprintf(buf, PAGE_SIZE, "%u\n", max_curr_avail_ma);
}

static struct device_attribute qpnp_flash_led_attrs[] = {
	__ATTR(strobe, (S_IRUGO | S_IWUSR | S_IWGRP),
				NULL,
				qpnp_led_strobe_type_store),
	__ATTR(reg_dump, (S_IRUGO | S_IWUSR | S_IWGRP),
				qpnp_flash_led_dump_regs_show,
				NULL),
	__ATTR(enable_current_derate, (S_IRUGO | S_IWUSR | S_IWGRP),
				NULL,
				qpnp_flash_led_current_derate_store),
	__ATTR(max_allowed_current, (S_IRUGO | S_IWUSR | S_IWGRP),
				qpnp_flash_led_max_current_show,
				NULL),
	__ATTR(enable_die_temp_current_derate, (S_IRUGO | S_IWUSR | S_IWGRP),
				NULL,
				qpnp_flash_led_die_temp_store),
};

static int qpnp_flash_led_get_thermal_derate_rate(const char *rate)
{
	if (strcmp(rate, "1_PERCENT") == 0)
		return RATE_1_PERCENT;
	else if (strcmp(rate, "1P25_PERCENT") == 0)
		return RATE_1P25_PERCENT;
	else if (strcmp(rate, "2_PERCENT") == 0)
		return RATE_2_PERCENT;
	else if (strcmp(rate, "2P5_PERCENT") == 0)
		return RATE_2P5_PERCENT;
	else if (strcmp(rate, "5_PERCENT") == 0)
		return RATE_5_PERCENT;
	else
		return RATE_5_PERCENT;
}

static int qpnp_flash_led_get_ramp_step(const char *step)
{
	if (strcmp(step, "0P2_US") == 0)
		return RAMP_STEP_0P2_US;
	else if (strcmp(step, "0P4_US") == 0)
		return RAMP_STEP_0P4_US;
	else if (strcmp(step, "0P8_US") == 0)
		return RAMP_STEP_0P8_US;
	else if (strcmp(step, "1P6_US") == 0)
		return RAMP_STEP_1P6_US;
	else if (strcmp(step, "3P3_US") == 0)
		return RAMP_STEP_3P3_US;
	else if (strcmp(step, "6P7_US") == 0)
		return RAMP_STEP_6P7_US;
	else if (strcmp(step, "13P5_US") == 0)
		return RAMP_STEP_13P5_US;
	else
		return RAMP_STEP_27US;
}

static u8 qpnp_flash_led_get_droop_debounce_time(u8 val)
{
	switch (val) {
	case 0:
		return 0;
	case 10:
		return 1;
	case 32:
		return 2;
	case 64:
		return 3;
	default:
		return 1;
	}
}

static u8 qpnp_flash_led_get_startup_dly(u8 val)
{
	switch (val) {
	case 10:
		return 0;
	case 32:
		return 1;
	case 64:
		return 2;
	case 128:
		return 3;
	default:
		return 3;
	}
}

static int
qpnp_flash_led_get_peripheral_type(struct qpnp_flash_led *led)
{
	int rc;
	u8 val;

	rc = spmi_ext_register_readl(led->spmi_dev->ctrl,
				led->spmi_dev->sid,
				FLASH_LED_PERIPHERAL_SUBTYPE(led->base),
				&val, 1);
	if (rc) {
		dev_err(&led->spmi_dev->dev,
				"Unable to read peripheral subtype\n");
		return -EINVAL;
	}

	return val;
}

static int qpnp_flash_led_module_disable(struct qpnp_flash_led *led,
				struct flash_node_data *flash_node)
{
	union power_supply_propval psy_prop;
	int rc, i;

	rc = qpnp_led_masked_write(led->spmi_dev,
			FLASH_LED_UNLOCK_SECURE(led->base),
			FLASH_SECURE_MASK, FLASH_UNLOCK_SECURE);
	if (rc) {
		dev_err(&led->spmi_dev->dev,
			"Secure reg write failed\n");
		return -EINVAL;
	}

	rc = qpnp_led_masked_write(led->spmi_dev,
			FLASH_TORCH(led->base),
			FLASH_TORCH_MASK, FLASH_LED_TORCH_DISABLE);
	if (rc) {
		dev_err(&led->spmi_dev->dev,
			"Torch reg write failed\n");
		return -EINVAL;
	}

	if (led->pdata->hdrm_sns_ch0_en) {
		if (flash_node->id == FLASH_LED_0 ||
				flash_node->id == FLASH_LED_SWITCH) {
			rc = qpnp_led_masked_write(led->spmi_dev,
				FLASH_HDRM_SNS_ENABLE_CTRL0(led->base),
				FLASH_LED_HDRM_SNS_ENABLE_MASK,
				FLASH_LED_HDRM_SNS_DISABLE);
			if (rc) {
				dev_err(&led->spmi_dev->dev,
					"Headroom sense disable failed\n");
				return rc;
			}
		}
	}

	if (led->pdata->hdrm_sns_ch1_en) {
		if (flash_node->id == FLASH_LED_1 ||
				flash_node->id == FLASH_LED_SWITCH) {
			rc = qpnp_led_masked_write(led->spmi_dev,
				FLASH_HDRM_SNS_ENABLE_CTRL1(led->base),
				FLASH_LED_HDRM_SNS_ENABLE_MASK,
				FLASH_LED_HDRM_SNS_DISABLE);
			if (rc) {
				dev_err(&led->spmi_dev->dev,
					"Headroom sense disable failed\n");
				return rc;
			}
		}
	}

	rc = qpnp_led_masked_write(led->spmi_dev,
			FLASH_MODULE_ENABLE_CTRL(led->base),
			FLASH_MODULE_ENABLE_MASK,
			FLASH_LED_MODULE_CTRL_DEFAULT);
	if (rc) {
		dev_err(&led->spmi_dev->dev, "Module disable failed\n");
		return -EINVAL;
	}

	if (led->pinctrl) {
		rc = pinctrl_select_state(led->pinctrl,
					led->gpio_state_suspend);
		if (rc) {
			dev_err(&led->spmi_dev->dev,
					"failed to disable GPIO\n");
			return -EINVAL;
		}
		led->gpio_enabled = false;
	}

	if (led->battery_psy) {
		psy_prop.intval = false;
		rc = led->battery_psy->set_property(led->battery_psy,
					POWER_SUPPLY_PROP_FLASH_ACTIVE,
							&psy_prop);
		if (rc) {
			dev_err(&led->spmi_dev->dev,
				"Failed to setup OTG pulse skip enable\n");
			return -EINVAL;
		}
	}

	if (flash_node->id == FLASH_LED_SWITCH)
		flash_node->trigger = 0;

	if (!(flash_node->trigger & FLASH_LED0_TRIGGER)) {
		rc = qpnp_led_masked_write(led->spmi_dev,
				led->current_addr,
				FLASH_CURRENT_MASK, 0x00);
		if (rc) {
			dev_err(&led->spmi_dev->dev,
				"current register write failed\n");
			return -EINVAL;
		}
	}

	if (!(flash_node->trigger & FLASH_LED1_TRIGGER)) {
		rc = qpnp_led_masked_write(led->spmi_dev,
				led->current2_addr,
				FLASH_CURRENT_MASK, 0x00);
		if (rc) {
			dev_err(&led->spmi_dev->dev,
				"current register write failed\n");
			return -EINVAL;
		}
	}

	for (i = 0; i < led->num_leds; i++)
		led->flash_node[i].flash_on = false;

	return 0;
}


static int flashlight_turn_off(void)
{
	int rc;
	bool flash_mode_on = (this_led->flash_node->type == FLASH && this_led->flash_node->flash_on);

	FLT_INFO_LOG("%s: flash_mode_on(%d)\n", __func__, flash_mode_on);
	mutex_lock(&this_led->flash_led_lock);

	rc = qpnp_led_masked_write(this_led->spmi_dev,
			FLASH_LED_STROBE_CTRL(this_led->base),
			this_led->flash_node->trigger, FLASH_LED_DISABLE);
	if (rc) {
		dev_err(&this_led->spmi_dev->dev, "Strobe disable failed\n");
		goto exit_flash_led_work;
	}

	usleep(FLASH_RAMP_DN_DELAY_US);

exit_flash_led_work:
	rc = qpnp_flash_led_module_disable(this_led, this_led->flash_node);
	if (rc) {
		dev_err(&this_led->spmi_dev->dev, "Module disable failed\n");
		goto exit_flash_led_work;
	}

	if(set_backlight && flash_mode_on)
		set_backlight(BACKLIGHT_ON);

	if (this_led->flash_node->boost_regulator && this_led->flash_node->flash_on) {
		regulator_disable(this_led->flash_node->boost_regulator);
		if (regulator_count_voltages(this_led->flash_node->boost_regulator) > 0)
			regulator_set_voltage(this_led->flash_node->boost_regulator,
				0, this_led->flash_node->boost_voltage_max);
	}

	this_led->flash_node->flash_on = false;
	mutex_unlock(&this_led->flash_led_lock);

	return 0;
}
static void flashlight_turn_off_work(struct work_struct *work)
{
	flashlight_turn_off();
}


int pmi8950_flash_mode(int mode2, int mode13)
{
	int rc;
	u8 val;
	union power_supply_propval psy_prop;
	int max_curr_avail_ma;

	this_led->flash_node->trigger = FLASH_LED0_TRIGGER | FLASH_LED1_TRIGGER;

	FLT_INFO_LOG("flash mode, camera flash current %d+%d.\n", mode2, mode13);

	if (mode2 == 0 && mode13 == 0)
	{
		flashlight_turn_off();
		return 0;
	}

	mutex_lock(&this_led->flash_led_lock);

	if (this_led->flash_node->boost_regulator && !this_led->flash_node->flash_on) {
		if (regulator_count_voltages(this_led->flash_node->boost_regulator)
									> 0) {
			rc = regulator_set_voltage(this_led->flash_node->boost_regulator,
				this_led->flash_node->boost_voltage_max,
				this_led->flash_node->boost_voltage_max);
			if (rc) {
				dev_err(&this_led->spmi_dev->dev,
				"boost regulator set voltage failed\n");
				mutex_unlock(&this_led->flash_led_lock);
				return -EINVAL;
			}
		}

		rc = regulator_enable(this_led->flash_node->boost_regulator);
		if (rc) {
			dev_err(&this_led->spmi_dev->dev,
				"Boost regulator enablement failed\n");
			goto error_regulator_enable;
		}
	}

	if (!this_led->gpio_enabled && this_led->pinctrl) {
		rc = pinctrl_select_state(this_led->pinctrl,
						this_led->gpio_state_active);
		if (rc) {
			dev_err(&this_led->spmi_dev->dev,
						"failed to enable GPIO\n");
			goto error_enable_gpio;
		}
		this_led->gpio_enabled = true;
	}

	if(set_backlight)
		set_backlight(BACKLIGHT_OFF);

	if (!this_led->battery_psy)
		this_led->battery_psy = power_supply_get_by_name("battery");
	if (!this_led->battery_psy) {
		dev_err(&this_led->spmi_dev->dev,
			"Failed to get battery power supply\n");
		goto exit_flash_led_work;
	}

	psy_prop.intval = true;
	rc = this_led->battery_psy->set_property(this_led->battery_psy,
					POWER_SUPPLY_PROP_FLASH_ACTIVE,
							&psy_prop);
	if (rc) {
		dev_err(&this_led->spmi_dev->dev,
			"Failed to setup OTG pulse skip enable\n");
		goto exit_flash_led_work;
	}

	if (this_led->pdata->power_detect_en) {
		max_curr_avail_ma =
			qpnp_flash_led_get_max_avail_current
						(this_led->flash_node, this_led);
		if (max_curr_avail_ma < 0) {
			dev_err(&this_led->spmi_dev->dev,
				"Failed to get Max available curr\n");
			goto exit_flash_led_work;
		} else {
			if (max_curr_avail_ma <
				this_led->flash_node->prgm_current) {
				dev_err(&this_led->spmi_dev->dev,
					"battery only supports %d mA.\n",
					max_curr_avail_ma);
				this_led->flash_node->prgm_current =
					(u16) max_curr_avail_ma;
			}
		}
	}

	val = 0x3B;	
	rc = qpnp_led_masked_write(this_led->spmi_dev,
		FLASH_SAFETY_TIMER(this_led->base),
		FLASH_SAFETY_TIMER_MASK, val);
	if (rc) {
		dev_err(&this_led->spmi_dev->dev,
			"Safety timer reg write failed\n");
		goto exit_flash_led_work;
	}

	rc = qpnp_led_masked_write(this_led->spmi_dev,
		FLASH_MAX_CURRENT(this_led->base),
		FLASH_CURRENT_MASK, FLASH_LED_MAX_FLASH_LEVEL(FLASH_LED_MAX_FLASH_CURRENT_MA));
	if (rc) {
		dev_err(&this_led->spmi_dev->dev,
			"Max current reg write failed\n");
		goto exit_flash_led_work;
	}

	if (mode2 > FLASH_LED_MAX_FLASH_CURRENT_MA)
		mode2 = FLASH_LED_MAX_FLASH_CURRENT_MA;

	val = (u8)FLASH_LED_MAX_FLASH_LEVEL(mode2);
	FLT_INFO_LOG("reg=0x1D342, val=0x%x\n", val);
	rc = qpnp_led_masked_write(this_led->spmi_dev,
			FLASH_LED0_CURRENT(this_led->base),
			FLASH_CURRENT_MASK, val);
	if (rc) {
		dev_err(&this_led->spmi_dev->dev,
			"Current reg write failed\n");
		goto exit_flash_led_work;
	}

	if (mode13 > FLASH_LED_MAX_FLASH_CURRENT_MA)
		mode13 = FLASH_LED_MAX_FLASH_CURRENT_MA;

	val = (u8)FLASH_LED_MAX_FLASH_LEVEL(mode13);
	FLT_INFO_LOG("reg=0x1D343, val=0x%x\n", val);
	rc = qpnp_led_masked_write(this_led->spmi_dev,
			FLASH_LED1_CURRENT(this_led->base),
			FLASH_CURRENT_MASK, val);
	if (rc) {
		dev_err(&this_led->spmi_dev->dev,
			"Current reg write failed\n");
		goto exit_flash_led_work;
	}

	rc = qpnp_led_masked_write(this_led->spmi_dev,
			FLASH_MODULE_ENABLE_CTRL(this_led->base),
			FLASH_MODULE_ENABLE | FLASH_LED0_ENABLEMENT | FLASH_LED1_ENABLEMENT,
			FLASH_MODULE_ENABLE | FLASH_LED0_ENABLEMENT | FLASH_LED1_ENABLEMENT);
	if (rc) {
		dev_err(&this_led->spmi_dev->dev,
			"Module enable reg write failed\n");
		goto exit_flash_led_work;
	}

	usleep(FLASH_RAMP_UP_DELAY_US);

	rc = qpnp_led_masked_write(this_led->spmi_dev,
		FLASH_LED_STROBE_CTRL(this_led->base),
		this_led->flash_node->trigger,
		this_led->flash_node->trigger);
	if (rc) {
		dev_err(&this_led->spmi_dev->dev,
			"Strobe reg write failed\n");
		goto exit_flash_led_work;
	}
	this_led->flash_node->type = FLASH;
	queue_delayed_work(pmi8950_work_queue, &pmi8950_delayed_work,
		   msecs_to_jiffies(FLASH_TIME_OUT));

	this_led->flash_node->flash_on = true;
	mutex_unlock(&this_led->flash_led_lock);

	return 0;

exit_flash_led_work:
	rc = qpnp_flash_led_module_disable(this_led, this_led->flash_node);
	if (rc) {
		dev_err(&this_led->spmi_dev->dev, "Module disable failed\n");
		goto exit_flash_led_work;
	}

	if(set_backlight)
		set_backlight(BACKLIGHT_ON);
error_enable_gpio:
	if (this_led->flash_node->boost_regulator && this_led->flash_node->flash_on) {
		regulator_disable(this_led->flash_node->boost_regulator);
error_regulator_enable:
	if (regulator_count_voltages(this_led->flash_node->boost_regulator) > 0)
		regulator_set_voltage(this_led->flash_node->boost_regulator,
			0, this_led->flash_node->boost_voltage_max);
	}

	this_led->flash_node->flash_on = false;
	mutex_unlock(&this_led->flash_led_lock);

	return -EINVAL;

}

int pmi8950_torch_mode(int mode2, int mode13)
{
	int rc;
	u8 val;
	this_led->flash_node->trigger = FLASH_LED0_TRIGGER | FLASH_LED1_TRIGGER;

	FLT_INFO_LOG("torch mode, camera flash current %d+%d.\n", mode2, mode13);

	if (mode2 == 0 && mode13 == 0)
	{
		flashlight_turn_off();
		return 0;
	}

	mutex_lock(&this_led->flash_led_lock);

	if (this_led->flash_node->boost_regulator && !this_led->flash_node->flash_on) {
		if (regulator_count_voltages(this_led->flash_node->boost_regulator) > 0) {
			rc = regulator_set_voltage(this_led->flash_node->boost_regulator,
				this_led->flash_node->boost_voltage_max,
				this_led->flash_node->boost_voltage_max);
			if (rc) {
				dev_err(&this_led->spmi_dev->dev,
				"boost regulator set voltage failed\n");
				mutex_unlock(&this_led->flash_led_lock);
				return -EINVAL;
			}
		}

		rc = regulator_enable(this_led->flash_node->boost_regulator);
		if (rc) {
			dev_err(&this_led->spmi_dev->dev,
				"Boost regulator enablement failed\n");
			goto error_regulator_enable;
		}
	}

	if (!this_led->gpio_enabled && this_led->pinctrl) {
		rc = pinctrl_select_state(this_led->pinctrl,
						this_led->gpio_state_active);
		if (rc) {
			dev_err(&this_led->spmi_dev->dev,
						"failed to enable GPIO\n");
			goto error_enable_gpio;
		}
		this_led->gpio_enabled = true;
	}

	rc = qpnp_led_masked_write(this_led->spmi_dev,
		FLASH_LED_UNLOCK_SECURE(this_led->base),
		FLASH_SECURE_MASK, FLASH_UNLOCK_SECURE);
	if (rc) {
		dev_err(&this_led->spmi_dev->dev,
			"Secure reg write failed\n");
		goto exit_flash_led_work;
	}

	rc = qpnp_led_masked_write(this_led->spmi_dev,
		FLASH_TORCH(this_led->base),
		FLASH_TORCH_MASK, FLASH_LED_TORCH_ENABLE);
	if (rc) {
		dev_err(&this_led->spmi_dev->dev,
			"Torch reg write failed\n");
		goto exit_flash_led_work;
	}

	if (mode2 > FLASH_LED_MAX_TORCH_CURRENT_MA)
		mode2 = FLASH_LED_MAX_TORCH_CURRENT_MA;
	val = (u8)FLASH_LED_MAX_FLASH_LEVEL(mode2);
	FLT_INFO_LOG("reg=0x1D342, val=0x%x\n", val);
	rc = qpnp_led_masked_write(this_led->spmi_dev,
		FLASH_LED0_CURRENT(this_led->base),
		FLASH_CURRENT_MASK, val);
	if (rc) {
		dev_err(&this_led->spmi_dev->dev,
			"Current reg write failed\n");
		goto exit_flash_led_work;
	}

	if (mode13 > FLASH_LED_MAX_TORCH_CURRENT_MA)
		mode13 = FLASH_LED_MAX_TORCH_CURRENT_MA;
	val = (u8)FLASH_LED_MAX_FLASH_LEVEL(mode13);
	FLT_INFO_LOG("reg=0x1D343, val=0x%x\n", val);
	rc = qpnp_led_masked_write(this_led->spmi_dev,
		FLASH_LED1_CURRENT(this_led->base),
		FLASH_CURRENT_MASK, val);
	if (rc) {
		dev_err(&this_led->spmi_dev->dev,
			"Current reg write failed\n");
		goto exit_flash_led_work;
	}

	rc = qpnp_led_masked_write(this_led->spmi_dev,
		FLASH_MAX_CURRENT(this_led->base),
		FLASH_CURRENT_MASK, FLASH_TORCH_MAX_LEVEL);
	if (rc) {
		dev_err(&this_led->spmi_dev->dev,
				"Max current reg write failed\n");
		goto exit_flash_led_work;
	}

	rc = qpnp_led_masked_write(this_led->spmi_dev,
		FLASH_MODULE_ENABLE_CTRL(this_led->base),
		FLASH_MODULE_ENABLE,
		FLASH_MODULE_ENABLE);
	if (rc) {
		dev_err(&this_led->spmi_dev->dev,
			"Module enable reg write failed\n");
		goto exit_flash_led_work;
	}

	rc = qpnp_led_masked_write(this_led->spmi_dev,
		FLASH_LED_STROBE_CTRL(this_led->base),
		FLASH_LED0_TRIGGER | FLASH_LED1_TRIGGER,
		FLASH_LED0_TRIGGER | FLASH_LED1_TRIGGER);
	if (rc) {
		dev_err(&this_led->spmi_dev->dev,
			"Strobe ctrl reg write failed\n");
		goto exit_flash_led_work;
	}
	this_led->flash_node->type = TORCH;

	this_led->flash_node->flash_on = true;
	mutex_unlock(&this_led->flash_led_lock);

	return 0;

exit_flash_led_work:
	rc = qpnp_flash_led_module_disable(this_led, this_led->flash_node);
	if (rc) {
		dev_err(&this_led->spmi_dev->dev, "Module disable failed\n");
		goto exit_flash_led_work;
	}
error_enable_gpio:
	if (this_led->flash_node->boost_regulator && this_led->flash_node->flash_on) {
		regulator_disable(this_led->flash_node->boost_regulator);
error_regulator_enable:
	if (regulator_count_voltages(this_led->flash_node->boost_regulator) > 0)
		regulator_set_voltage(this_led->flash_node->boost_regulator,
			0, this_led->flash_node->boost_voltage_max);
	}


	this_led->flash_node->flash_on = false;
	mutex_unlock(&this_led->flash_led_lock);

	return -EINVAL;

}

static enum
led_brightness qpnp_flash_led_brightness_get(struct led_classdev *led_cdev)
{
	return led_cdev->brightness;
}

static void qpnp_flash_led_work(struct work_struct *work)
{
	struct flash_node_data *flash_node = container_of(work,
				struct flash_node_data, work);
	struct qpnp_flash_led *led =
			dev_get_drvdata(&flash_node->spmi_dev->dev);
	union power_supply_propval psy_prop;
	int rc, brightness = flash_node->cdev.brightness;
	int max_curr_avail_ma = 0;
	int total_curr_ma = 0;
	int i;
	u8 val;

	FLT_INFO_LOG("%s: brt = %d\n", __func__, brightness);
	mutex_lock(&led->flash_led_lock);

	if (!brightness)
		goto turn_off;

	if (flash_node->boost_regulator && !flash_node->flash_on) {
		if (regulator_count_voltages(flash_node->boost_regulator) > 0) {
			rc = regulator_set_voltage(flash_node->boost_regulator,
					flash_node->boost_voltage_max,
					flash_node->boost_voltage_max);
			if (rc) {
				dev_err(&led->spmi_dev->dev,
					"boost regulator set voltage failed\n");
				mutex_unlock(&led->flash_led_lock);
				return;
			}
		}

		rc = regulator_enable(flash_node->boost_regulator);
		if (rc) {
			dev_err(&led->spmi_dev->dev,
				"Boost regulator enablement failed\n");
			goto error_regulator_enable;
		}
	}

	if (!led->gpio_enabled && led->pinctrl) {
		rc = pinctrl_select_state(led->pinctrl,
						led->gpio_state_active);
		if (rc) {
			dev_err(&led->spmi_dev->dev,
						"failed to enable GPIO\n");
			goto error_enable_gpio;
		}
		led->gpio_enabled = true;
	}

	if (led->dbg_feature_en) {
		rc = qpnp_led_masked_write(led->spmi_dev,
						INT_SET_TYPE(led->base),
						FLASH_STATUS_REG_MASK, 0x1F);
		if (rc) {
			dev_err(&led->spmi_dev->dev,
					"INT_SET_TYPE write failed\n");
			goto exit_flash_led_work;
		}

		rc = qpnp_led_masked_write(led->spmi_dev,
					IN_POLARITY_HIGH(led->base),
					FLASH_STATUS_REG_MASK, 0x1F);
		if (rc) {
			dev_err(&led->spmi_dev->dev,
					"IN_POLARITY_HIGH write failed\n");
			goto exit_flash_led_work;
		}

		rc = qpnp_led_masked_write(led->spmi_dev,
					INT_EN_SET(led->base),
					FLASH_STATUS_REG_MASK, 0x1F);
		if (rc) {
			dev_err(&led->spmi_dev->dev,
					"INT_EN_SET write failed\n");
			goto exit_flash_led_work;
		}

		rc = qpnp_led_masked_write(led->spmi_dev,
					INT_LATCHED_CLR(led->base),
					FLASH_STATUS_REG_MASK, 0x1F);
		if (rc) {
			dev_err(&led->spmi_dev->dev,
					"INT_LATCHED_CLR write failed\n");
			goto exit_flash_led_work;
		}
	}

	if (flash_node->type == DUAL_LEDS) {
		if (flash_node->prgm_current == FBAD_FULL) {
			if(set_backlight)
				set_backlight(BACKLIGHT_OFF);

			val = 0x3B;	
			rc = qpnp_led_masked_write(led->spmi_dev,
				FLASH_SAFETY_TIMER(led->base),
				FLASH_SAFETY_TIMER_MASK, val);
			if (rc) {
				dev_err(&led->spmi_dev->dev,
					"Safety timer reg write failed\n");
				goto exit_flash_led_work;
			}

			rc = qpnp_led_masked_write(led->spmi_dev,
				FLASH_MAX_CURRENT(led->base),
				FLASH_CURRENT_MASK, FLASH_LED_MAX_FLASH_LEVEL(FLASH_LED_MAX_FLASH_CURRENT_MA));
			if (rc) {
				dev_err(&led->spmi_dev->dev,
					"Max current reg write failed\n");
				goto exit_flash_led_work;
			}

			val = 0x3B; 
			rc = qpnp_led_masked_write(led->spmi_dev,
					FLASH_LED0_CURRENT(led->base),
					FLASH_CURRENT_MASK, val);
			if (rc) {
				dev_err(&led->spmi_dev->dev,
					"Current reg write failed\n");
				goto exit_flash_led_work;
			}

			rc = qpnp_led_masked_write(led->spmi_dev,
					FLASH_LED1_CURRENT(led->base),
					FLASH_CURRENT_MASK, val);
			if (rc) {
				dev_err(&led->spmi_dev->dev,
					"Current reg write failed\n");
				goto exit_flash_led_work;
			}

			rc = qpnp_led_masked_write(led->spmi_dev,
					FLASH_MODULE_ENABLE_CTRL(led->base),
					FLASH_MODULE_ENABLE | FLASH_LED0_ENABLEMENT | FLASH_LED1_ENABLEMENT,
					FLASH_MODULE_ENABLE | FLASH_LED0_ENABLEMENT | FLASH_LED1_ENABLEMENT);
			if (rc) {
				dev_err(&led->spmi_dev->dev,
					"Module enable reg write failed\n");
				goto exit_flash_led_work;
			}

			usleep(FLASH_RAMP_UP_DELAY_US);

			rc = qpnp_led_masked_write(led->spmi_dev,
				FLASH_LED_STROBE_CTRL(led->base),
				FLASH_LED0_TRIGGER | FLASH_LED1_TRIGGER,
				FLASH_LED0_TRIGGER | FLASH_LED1_TRIGGER);
			if (rc) {
				dev_err(&led->spmi_dev->dev,
					"Strobe reg write failed\n");
				goto exit_flash_led_work;
			}

		} else {	
			rc = qpnp_led_masked_write(led->spmi_dev,
				FLASH_LED_UNLOCK_SECURE(led->base),
				FLASH_SECURE_MASK, FLASH_UNLOCK_SECURE);
			if (rc) {
				dev_err(&led->spmi_dev->dev,
					"Secure reg write failed\n");
				goto exit_flash_led_work;
			}

			rc = qpnp_led_masked_write(led->spmi_dev,
				FLASH_TORCH(led->base),
				FLASH_TORCH_MASK, FLASH_LED_TORCH_ENABLE);
			if (rc) {
				dev_err(&led->spmi_dev->dev,
					"Torch reg write failed\n");
				goto exit_flash_led_work;
			}

			if (flash_node->prgm_current == FBAD_TORCH) {
				val = 0x03;
				rc = qpnp_led_masked_write(led->spmi_dev,
					FLASH_LED0_CURRENT(led->base),
					FLASH_CURRENT_MASK, val);
				if (rc) {
					dev_err(&led->spmi_dev->dev,
						"Current reg write failed\n");
					goto exit_flash_led_work;
				}

				rc = qpnp_led_masked_write(led->spmi_dev,
					FLASH_LED1_CURRENT(led->base),
					FLASH_CURRENT_MASK, val);
				if (rc) {
					dev_err(&led->spmi_dev->dev,
						"Current reg write failed\n");
					goto exit_flash_led_work;
				}

			} else if ( (flash_node->prgm_current == FBAD_TORCH1) ||
					(flash_node->prgm_current == FBAD_PREFLASH) ) {
				val = 0x07;	
				rc = qpnp_led_masked_write(led->spmi_dev,
					FLASH_LED0_CURRENT(led->base),
					FLASH_CURRENT_MASK, val);
				if (rc) {
					dev_err(&led->spmi_dev->dev,
						"Current reg write failed\n");
					goto exit_flash_led_work;
				}

				val = 0x03;	
				rc = qpnp_led_masked_write(led->spmi_dev,
					FLASH_LED1_CURRENT(led->base),
					FLASH_CURRENT_MASK, val);
				if (rc) {
					dev_err(&led->spmi_dev->dev,
						"Current reg write failed\n");
					goto exit_flash_led_work;
				}
			} else {

				val = 0x0B;	
				rc = qpnp_led_masked_write(led->spmi_dev,
					FLASH_LED0_CURRENT(led->base),
					FLASH_CURRENT_MASK, val);
				if (rc) {
					dev_err(&led->spmi_dev->dev,
						"Current reg write failed\n");
					goto exit_flash_led_work;
				}

				val = 0x03;	
				rc = qpnp_led_masked_write(led->spmi_dev,
					FLASH_LED1_CURRENT(led->base),
					FLASH_CURRENT_MASK, val);
				if (rc) {
					dev_err(&led->spmi_dev->dev,
						"Current reg write failed\n");
					goto exit_flash_led_work;
				}
			}

			rc = qpnp_led_masked_write(led->spmi_dev,
				FLASH_MAX_CURRENT(led->base),
				FLASH_CURRENT_MASK, FLASH_TORCH_MAX_LEVEL);
			if (rc) {
				dev_err(&led->spmi_dev->dev,
						"Max current reg write failed\n");
				goto exit_flash_led_work;
			}

			rc = qpnp_led_masked_write(led->spmi_dev,
				FLASH_MODULE_ENABLE_CTRL(led->base),
				FLASH_MODULE_ENABLE,
				FLASH_MODULE_ENABLE);
			if (rc) {
				dev_err(&led->spmi_dev->dev,
					"Module enable reg write failed\n");
				goto exit_flash_led_work;
			}

			rc = qpnp_led_masked_write(led->spmi_dev,
				FLASH_LED_STROBE_CTRL(led->base),
				FLASH_LED0_TRIGGER | FLASH_LED1_TRIGGER,
				FLASH_LED0_TRIGGER | FLASH_LED1_TRIGGER);
			if (rc) {
				dev_err(&led->spmi_dev->dev,
					"Strobe ctrl reg write failed\n");
				goto exit_flash_led_work;
			}

		}
	} else if (flash_node->type == TORCH) {
		rc = qpnp_led_masked_write(led->spmi_dev,
			FLASH_LED_UNLOCK_SECURE(led->base),
			FLASH_SECURE_MASK, FLASH_UNLOCK_SECURE);
		if (rc) {
			dev_err(&led->spmi_dev->dev,
				"Secure reg write failed\n");
			goto exit_flash_led_work;
		}

		rc = qpnp_led_masked_write(led->spmi_dev,
			FLASH_TORCH(led->base),
			FLASH_TORCH_MASK, FLASH_LED_TORCH_ENABLE);
		if (rc) {
			dev_err(&led->spmi_dev->dev,
				"Torch reg write failed\n");
			goto exit_flash_led_work;
		}

		if (flash_node->id == FLASH_LED_SWITCH) {
			val = (u8)(flash_node->prgm_current *
						FLASH_TORCH_MAX_LEVEL
						/ flash_node->max_current);
			rc = qpnp_led_masked_write(led->spmi_dev,
						led->current_addr,
						FLASH_CURRENT_MASK, val);
			if (rc) {
				dev_err(&led->spmi_dev->dev,
					"Torch reg write failed\n");
				goto exit_flash_led_work;
			}

			val = (u8)(flash_node->prgm_current2 *
						FLASH_TORCH_MAX_LEVEL
						/ flash_node->max_current);
			rc = qpnp_led_masked_write(led->spmi_dev,
					led->current2_addr,
					FLASH_CURRENT_MASK, val);
			if (rc) {
				dev_err(&led->spmi_dev->dev,
					"Torch reg write failed\n");
				goto exit_flash_led_work;
			}
		} else {
			val = (u8)(flash_node->prgm_current *
						FLASH_TORCH_MAX_LEVEL /
						flash_node->max_current);
			if (flash_node->id == FLASH_LED_0) {
				rc = qpnp_led_masked_write(led->spmi_dev,
						led->current_addr,
						FLASH_CURRENT_MASK, val);
				if (rc) {
					dev_err(&led->spmi_dev->dev,
						"current reg write failed\n");
					goto exit_flash_led_work;
				}
			} else {
				rc = qpnp_led_masked_write(led->spmi_dev,
						led->current2_addr,
						FLASH_CURRENT_MASK, val);
				if (rc) {
					dev_err(&led->spmi_dev->dev,
						"current reg write failed\n");
					goto exit_flash_led_work;
				}
			}
		}

		rc = qpnp_led_masked_write(led->spmi_dev,
			FLASH_MAX_CURRENT(led->base),
			FLASH_CURRENT_MASK, FLASH_TORCH_MAX_LEVEL);
		if (rc) {
			dev_err(&led->spmi_dev->dev,
					"Max current reg write failed\n");
			goto exit_flash_led_work;
		}

		rc = qpnp_led_masked_write(led->spmi_dev,
			FLASH_MODULE_ENABLE_CTRL(led->base),
			FLASH_MODULE_ENABLE_MASK, FLASH_MODULE_ENABLE);
		if (rc) {
			dev_err(&led->spmi_dev->dev,
				"Module enable reg write failed\n");
			goto exit_flash_led_work;
		}

		if (led->pdata->hdrm_sns_ch0_en ||
						led->pdata->hdrm_sns_ch1_en) {
			if (flash_node->id == FLASH_LED_SWITCH) {
				rc = qpnp_led_masked_write(led->spmi_dev,
					FLASH_HDRM_SNS_ENABLE_CTRL0(led->base),
					FLASH_LED_HDRM_SNS_ENABLE_MASK,
					flash_node->trigger &
					FLASH_LED0_TRIGGER ?
					FLASH_LED_HDRM_SNS_ENABLE :
					FLASH_LED_HDRM_SNS_DISABLE);
				if (rc) {
					dev_err(&led->spmi_dev->dev,
					"Headroom sense enable failed\n");
					goto exit_flash_led_work;
				}

				rc = qpnp_led_masked_write(led->spmi_dev,
					FLASH_HDRM_SNS_ENABLE_CTRL1(led->base),
					FLASH_LED_HDRM_SNS_ENABLE_MASK,
					flash_node->trigger &
					FLASH_LED1_TRIGGER ?
					FLASH_LED_HDRM_SNS_ENABLE :
					FLASH_LED_HDRM_SNS_DISABLE);
				if (rc) {
					dev_err(&led->spmi_dev->dev,
					"Headroom sense enable failed\n");
					goto exit_flash_led_work;
				}
			} else if (flash_node->id == FLASH_LED_0) {
				rc = qpnp_led_masked_write(led->spmi_dev,
					FLASH_HDRM_SNS_ENABLE_CTRL0(led->base),
					FLASH_LED_HDRM_SNS_ENABLE_MASK,
					FLASH_LED_HDRM_SNS_ENABLE);
				if (rc) {
					dev_err(&led->spmi_dev->dev,
					"Headroom sense disable failed\n");
					goto exit_flash_led_work;
				}
			} else if (flash_node->id == FLASH_LED_1) {
				rc = qpnp_led_masked_write(led->spmi_dev,
					FLASH_HDRM_SNS_ENABLE_CTRL1(led->base),
					FLASH_LED_HDRM_SNS_ENABLE_MASK,
					FLASH_LED_HDRM_SNS_ENABLE);
				if (rc) {
					dev_err(&led->spmi_dev->dev,
					"Headroom sense diable failed\n");
					goto exit_flash_led_work;
				}
			}
		}

		rc = qpnp_led_masked_write(led->spmi_dev,
			FLASH_LED_STROBE_CTRL(led->base),
			(flash_node->id == FLASH_LED_SWITCH ? FLASH_STROBE_MASK
							: flash_node->trigger),
							flash_node->trigger);
		if (rc) {
			dev_err(&led->spmi_dev->dev,
				"Strobe reg write failed\n");
			goto exit_flash_led_work;
		}
	} else if (flash_node->type == FLASH) {
		if (flash_node->trigger & FLASH_LED0_TRIGGER)
			max_curr_avail_ma += flash_node->max_current;
		if (flash_node->trigger & FLASH_LED1_TRIGGER)
			max_curr_avail_ma += flash_node->max_current;

		psy_prop.intval = true;
		rc = led->battery_psy->set_property(led->battery_psy,
						POWER_SUPPLY_PROP_FLASH_ACTIVE,
								&psy_prop);
		if (rc) {
			dev_err(&led->spmi_dev->dev,
				"Failed to setup OTG pulse skip enable\n");
			goto exit_flash_led_work;
		}

		if (led->pdata->power_detect_en ||
					led->pdata->die_current_derate_en) {
			if (led->battery_psy) {
				led->battery_psy->get_property(led->battery_psy,
					POWER_SUPPLY_PROP_STATUS,
					&psy_prop);
				if (psy_prop.intval < 0) {
					dev_err(&led->spmi_dev->dev,
						"Invalid battery status\n");
					goto exit_flash_led_work;
				}

				if (psy_prop.intval ==
						POWER_SUPPLY_STATUS_CHARGING)
					led->charging_enabled = true;
				else if (psy_prop.intval ==
					POWER_SUPPLY_STATUS_DISCHARGING
					|| psy_prop.intval ==
					POWER_SUPPLY_STATUS_NOT_CHARGING)
					led->charging_enabled = false;
			}
			max_curr_avail_ma =
				qpnp_flash_led_get_max_avail_current
							(flash_node, led);
			if (max_curr_avail_ma < 0) {
				dev_err(&led->spmi_dev->dev,
					"Failed to get max avail curr\n");
				goto exit_flash_led_work;
			}
		}

		if (flash_node->id == FLASH_LED_SWITCH) {
			if (flash_node->trigger & FLASH_LED0_TRIGGER)
				total_curr_ma += flash_node->prgm_current;
			else if (flash_node->trigger & FLASH_LED1_TRIGGER)
				total_curr_ma += flash_node->prgm_current2;

			if (max_curr_avail_ma < total_curr_ma) {
				flash_node->prgm_current *=
					max_curr_avail_ma / total_curr_ma;
				flash_node->prgm_current2 *=
					max_curr_avail_ma / total_curr_ma;
			}

			val = (u8)(flash_node->prgm_current *
				FLASH_MAX_LEVEL / flash_node->max_current);
			rc = qpnp_led_masked_write(led->spmi_dev,
				led->current_addr, FLASH_CURRENT_MASK, val);
			if (rc) {
				dev_err(&led->spmi_dev->dev,
					"Current register write failed\n");
				goto exit_flash_led_work;
			}

			val = (u8)(flash_node->prgm_current2 *
				FLASH_MAX_LEVEL / flash_node->max_current);
			rc = qpnp_led_masked_write(led->spmi_dev,
				led->current2_addr, FLASH_CURRENT_MASK, val);
			if (rc) {
				dev_err(&led->spmi_dev->dev,
					"Current register write failed\n");
				goto exit_flash_led_work;
			}
		} else {
			if (led->pdata->power_detect_en &&
					max_curr_avail_ma <
					flash_node->prgm_current) {
				dev_err(&led->spmi_dev->dev,
					"battery only supprots %d mA\n",
					max_curr_avail_ma);
				flash_node->prgm_current =
					 (u16)max_curr_avail_ma;
			}

			val = (u8)(flash_node->prgm_current *
					 FLASH_MAX_LEVEL
					/ flash_node->max_current);
			if (flash_node->id == FLASH_LED_0) {
				rc = qpnp_led_masked_write(
					led->spmi_dev,
					led->current_addr,
					FLASH_CURRENT_MASK, val);
				if (rc) {
					dev_err(&led->spmi_dev->dev,
						"current reg write failed\n");
					goto exit_flash_led_work;
				}
			} else if (flash_node->id == FLASH_LED_1) {
				rc = qpnp_led_masked_write(
					led->spmi_dev,
					led->current2_addr,
					FLASH_CURRENT_MASK, val);
				if (rc) {
					dev_err(&led->spmi_dev->dev,
						"current reg write failed\n");
					goto exit_flash_led_work;
				}
			}
		}

		val = (u8)((flash_node->duration - FLASH_DURATION_DIVIDER)
						/ FLASH_DURATION_DIVIDER);
		rc = qpnp_led_masked_write(led->spmi_dev,
			FLASH_SAFETY_TIMER(led->base),
			FLASH_SAFETY_TIMER_MASK, val);
		if (rc) {
			dev_err(&led->spmi_dev->dev,
				"Safety timer reg write failed\n");
			goto exit_flash_led_work;
		}

		rc = qpnp_led_masked_write(led->spmi_dev,
			FLASH_MAX_CURRENT(led->base),
			FLASH_CURRENT_MASK, FLASH_MAX_LEVEL);
		if (rc) {
			dev_err(&led->spmi_dev->dev,
				"Max current reg write failed\n");
			goto exit_flash_led_work;
		}

		if (!led->charging_enabled) {
			rc = qpnp_led_masked_write(led->spmi_dev,
				FLASH_MODULE_ENABLE_CTRL(led->base),
				FLASH_MODULE_ENABLE, FLASH_MODULE_ENABLE);
			if (rc) {
				dev_err(&led->spmi_dev->dev,
					"Module enable reg write failed\n");
				goto exit_flash_led_work;
			}

			usleep(FLASH_RAMP_UP_DELAY_US);
		}

		if (led->pdata->hdrm_sns_ch0_en ||
					led->pdata->hdrm_sns_ch1_en) {
			if (flash_node->id == FLASH_LED_SWITCH) {
				rc = qpnp_led_masked_write(led->spmi_dev,
					FLASH_HDRM_SNS_ENABLE_CTRL0(led->base),
					FLASH_LED_HDRM_SNS_ENABLE_MASK,
					(flash_node->trigger &
					FLASH_LED0_TRIGGER ?
					FLASH_LED_HDRM_SNS_ENABLE :
					FLASH_LED_HDRM_SNS_DISABLE));
				if (rc) {
					dev_err(&led->spmi_dev->dev,
					"Headroom sense enable failed\n");
					goto exit_flash_led_work;
				}

				rc = qpnp_led_masked_write(led->spmi_dev,
					FLASH_HDRM_SNS_ENABLE_CTRL1(led->base),
					FLASH_LED_HDRM_SNS_ENABLE_MASK,
					(flash_node->trigger &
					FLASH_LED1_TRIGGER ?
					FLASH_LED_HDRM_SNS_ENABLE :
					FLASH_LED_HDRM_SNS_DISABLE));
				if (rc) {
					dev_err(&led->spmi_dev->dev,
					"Headroom sense enable failed\n");
					goto exit_flash_led_work;
				}
			} else if (flash_node->id == FLASH_LED_0) {
				rc = qpnp_led_masked_write(led->spmi_dev,
					FLASH_HDRM_SNS_ENABLE_CTRL0(led->base),
					FLASH_LED_HDRM_SNS_ENABLE_MASK,
					FLASH_LED_HDRM_SNS_ENABLE);
				if (rc) {
					dev_err(&led->spmi_dev->dev,
					"Headroom sense disable failed\n");
					goto exit_flash_led_work;
				}
			} else if (flash_node->id == FLASH_LED_1) {
				rc = qpnp_led_masked_write(led->spmi_dev,
					FLASH_HDRM_SNS_ENABLE_CTRL1(led->base),
					FLASH_LED_HDRM_SNS_ENABLE_MASK,
					FLASH_LED_HDRM_SNS_ENABLE);
				if (rc) {
					dev_err(&led->spmi_dev->dev,
					"Headroom sense disable failed\n");
					goto exit_flash_led_work;
				}
			}
		}

		rc = qpnp_led_masked_write(led->spmi_dev,
			FLASH_LED_STROBE_CTRL(led->base),
			(flash_node->id == FLASH_LED_SWITCH ? FLASH_STROBE_MASK
							: flash_node->trigger),
							flash_node->trigger);
		if (rc) {
			dev_err(&led->spmi_dev->dev,
				"Strobe reg write failed\n");
			goto exit_flash_led_work;
		}

		if (led->strobe_debug && led->dbg_feature_en) {
			udelay(2000);
			rc = spmi_ext_register_readl(led->spmi_dev->ctrl,
					led->spmi_dev->sid,
					FLASH_LED_FAULT_STATUS(led->base),
					&val, 1);
			if (rc) {
				dev_err(&led->spmi_dev->dev,
				"Unable to read from addr= %x, rc(%d)\n",
				FLASH_LED_FAULT_STATUS(led->base), rc);
				goto exit_flash_led_work;
			}
			led->fault_reg = val;
		}
	} else {
		pr_err("Both Torch and Flash cannot be select at same time\n");
		for (i = 0; i < led->num_leds; i++)
			led->flash_node[i].flash_on = false;
		goto turn_off;
	}

	flash_node->flash_on = true;
	mutex_unlock(&led->flash_led_lock);

	return;

turn_off:
	rc = qpnp_led_masked_write(led->spmi_dev,
			FLASH_LED_STROBE_CTRL(led->base),
			flash_node->trigger, FLASH_LED_DISABLE);
	if (rc) {
		dev_err(&led->spmi_dev->dev, "Strobe disable failed\n");
		goto exit_flash_led_work;
	}

	usleep(FLASH_RAMP_DN_DELAY_US);

exit_flash_led_work:
	rc = qpnp_flash_led_module_disable(led, flash_node);
	if (rc) {
		dev_err(&led->spmi_dev->dev, "Module disable failed\n");
		goto exit_flash_led_work;
	}
	if(set_backlight)
		set_backlight(BACKLIGHT_ON);
error_enable_gpio:
	if (flash_node->boost_regulator && flash_node->flash_on) {
		regulator_disable(flash_node->boost_regulator);
error_regulator_enable:
		if (regulator_count_voltages(flash_node->boost_regulator) > 0)
			regulator_set_voltage(flash_node->boost_regulator,
				0, flash_node->boost_voltage_max);
	}

	flash_node->flash_on = false;
	mutex_unlock(&led->flash_led_lock);

	return;
}

static void qpnp_flash_led_brightness_set(struct led_classdev *led_cdev,
						enum led_brightness value)
{
	struct flash_node_data *flash_node;
	struct qpnp_flash_led *led;
	flash_node = container_of(led_cdev, struct flash_node_data, cdev);
	led = dev_get_drvdata(&flash_node->spmi_dev->dev);

	if (value < LED_OFF) {
		pr_err("Invalid brightness value\n");
		return;
	}

	if (value > flash_node->cdev.max_brightness)
		value = flash_node->cdev.max_brightness;

	flash_node->cdev.brightness = value;
	if (flash_node->id == FLASH_LED_2) {
		if (value < FLASH_LED_MIN_CURRENT_MA && value != 0)
			value = FLASH_LED_MIN_CURRENT_MA;
		flash_node->prgm_current = value;
	} else if (led->flash_node[led->num_leds - 1].id ==
						FLASH_LED_SWITCH) {
		if (flash_node->type == TORCH)
			led->flash_node[led->num_leds - 1].type = TORCH;
		else if (flash_node->type == FLASH)
			led->flash_node[led->num_leds - 1].type = FLASH;

		led->flash_node[led->num_leds - 1].max_current
						= flash_node->max_current;

		if (flash_node->id == FLASH_LED_0 ||
					 flash_node->id == FLASH_LED_1) {
			if (value < FLASH_LED_MIN_CURRENT_MA && value != 0)
				value = FLASH_LED_MIN_CURRENT_MA;

			flash_node->prgm_current = value;
			flash_node->flash_on = value ? true : false;
			if (value) {
				led->flash_node[led->num_leds - 1].trigger |=
						(0x80 >> flash_node->id);
				if (flash_node->id == FLASH_LED_0)
					led->flash_node[led->num_leds - 1].
					prgm_current = flash_node->prgm_current;
				else if (flash_node->id == FLASH_LED_1)
					led->flash_node[led->num_leds - 1].
					prgm_current2 =
					flash_node->prgm_current;
			} else {
				led->flash_node[led->num_leds - 1].trigger &=
						~(0x80 >> flash_node->id);
			}

			return;
		} else if (flash_node->id == FLASH_LED_SWITCH) {
			if (!value) {
				flash_node->prgm_current = 0;
				flash_node->prgm_current2 = 0;
			}
		}
	} else {
		if (value < FLASH_LED_MIN_CURRENT_MA && value != 0)
			value = FLASH_LED_MIN_CURRENT_MA;
		flash_node->prgm_current = value;
	}

	queue_work(led->ordered_workq, &flash_node->work);

	return;
}

static int qpnp_flash_led_init_settings(struct qpnp_flash_led *led)
{
	int rc;
	u8 val, temp_val;

	rc = qpnp_led_masked_write(led->spmi_dev,
			FLASH_MODULE_ENABLE_CTRL(led->base),
			FLASH_MODULE_ENABLE_MASK,
			FLASH_LED_MODULE_CTRL_DEFAULT);
	if (rc) {
		dev_err(&led->spmi_dev->dev, "Module disable failed\n");
		return rc;
	}

	rc = qpnp_led_masked_write(led->spmi_dev,
			FLASH_LED_STROBE_CTRL(led->base),
			FLASH_STROBE_MASK, FLASH_LED_DISABLE);
	if (rc) {
		dev_err(&led->spmi_dev->dev, "Strobe disable failed\n");
		return rc;
	}

	rc = qpnp_led_masked_write(led->spmi_dev,
					FLASH_LED_TMR_CTRL(led->base),
					FLASH_TMR_MASK, FLASH_TMR_SAFETY);
	if (rc) {
		dev_err(&led->spmi_dev->dev,
			"LED timer ctrl reg write failed(%d)\n", rc);
		return rc;
	}

	val = (u8)(led->pdata->headroom / FLASH_LED_HEADROOM_DIVIDER -
						FLASH_LED_HEADROOM_OFFSET);
	rc = qpnp_led_masked_write(led->spmi_dev,
						FLASH_HEADROOM(led->base),
						FLASH_HEADROOM_MASK, val);
	if (rc) {
		dev_err(&led->spmi_dev->dev, "Headroom reg write failed\n");
		return rc;
	}

	val = qpnp_flash_led_get_startup_dly(led->pdata->startup_dly);

	rc = qpnp_led_masked_write(led->spmi_dev,
					FLASH_STARTUP_DELAY(led->base),
						FLASH_STARTUP_DLY_MASK, val);
	if (rc) {
		dev_err(&led->spmi_dev->dev,
					"Startup delay reg write failed\n");
		return rc;
	}

	val = (u8)(led->pdata->clamp_current * FLASH_MAX_LEVEL /
						FLASH_LED_MAX_CURRENT_MA);
	rc = qpnp_led_masked_write(led->spmi_dev,
					FLASH_CLAMP_CURRENT(led->base),
						FLASH_CURRENT_MASK, val);
	if (rc) {
		dev_err(&led->spmi_dev->dev,
					"Clamp current reg write failed\n");
		return rc;
	}

	if (led->pdata->pmic_charger_support)
		val = FLASH_LED_FLASH_HW_VREG_OK;
	else
		val = FLASH_LED_FLASH_SW_VREG_OK;
	rc = qpnp_led_masked_write(led->spmi_dev,
					FLASH_VREG_OK_FORCE(led->base),
						FLASH_VREG_OK_FORCE_MASK, val);
	if (rc) {
		dev_err(&led->spmi_dev->dev,
					"VREG OK force reg write failed\n");
		return rc;
	}

	if (led->pdata->self_check_en)
		val = FLASH_MODULE_ENABLE;
	else
		val = FLASH_LED_DISABLE;
	rc = qpnp_led_masked_write(led->spmi_dev,
					FLASH_FAULT_DETECT(led->base),
						FLASH_FAULT_DETECT_MASK, val);
	if (rc) {
		dev_err(&led->spmi_dev->dev,
					"Fault detect reg write failed\n");
		return rc;
	}

	val = 0x0;
	val |= led->pdata->mask3_en << FLASH_LED_MASK3_ENABLE_SHIFT;
	val |= FLASH_LED_MASK_MODULE_MASK2_ENABLE;
	rc = qpnp_led_masked_write(led->spmi_dev, FLASH_MASK_ENABLE(led->base),
				FLASH_MASK_MODULE_CONTRL_MASK, val);
	if (rc) {
		dev_err(&led->spmi_dev->dev, "Mask module enable failed\n");
		return rc;
	}

	rc = spmi_ext_register_readl(led->spmi_dev->ctrl,
			led->spmi_dev->sid,
			FLASH_PERPH_RESET_CTRL(led->base),
			&val, 1);
	if (rc) {
		dev_err(&led->spmi_dev->dev,
			"Unable to read from address %x, rc(%d)\n",
			FLASH_PERPH_RESET_CTRL(led->base), rc);
		return -EINVAL;
	}

	if (led->pdata->follow_rb_disable) {
		rc = qpnp_led_masked_write(led->spmi_dev,
				FLASH_LED_UNLOCK_SECURE(led->base),
				FLASH_SECURE_MASK, FLASH_UNLOCK_SECURE);
		if (rc) {
			dev_err(&led->spmi_dev->dev,
				"Secure reg write failed\n");
			return -EINVAL;
		}

		val |= FLASH_FOLLOW_OTST2_RB_MASK;
		rc = qpnp_led_masked_write(led->spmi_dev,
				FLASH_PERPH_RESET_CTRL(led->base),
				FLASH_FOLLOW_OTST2_RB_MASK, val);
		if (rc) {
			dev_err(&led->spmi_dev->dev,
				"failed to reset OTST2_RB bit\n");
			return rc;
		}
	} else {
		rc = qpnp_led_masked_write(led->spmi_dev,
				FLASH_LED_UNLOCK_SECURE(led->base),
				FLASH_SECURE_MASK, FLASH_UNLOCK_SECURE);
		if (rc) {
			dev_err(&led->spmi_dev->dev,
				"Secure reg write failed\n");
			return -EINVAL;
		}

		val &= ~FLASH_FOLLOW_OTST2_RB_MASK;
		rc = qpnp_led_masked_write(led->spmi_dev,
				FLASH_PERPH_RESET_CTRL(led->base),
				FLASH_FOLLOW_OTST2_RB_MASK, val);
		if (rc) {
			dev_err(&led->spmi_dev->dev,
				"failed to reset OTST2_RB bit\n");
			return rc;
		}
	}

	if (!led->pdata->thermal_derate_en)
		val = 0x0;
	else {
		val = led->pdata->thermal_derate_en << 7;
		val |= led->pdata->thermal_derate_rate << 3;
		val |= (led->pdata->thermal_derate_threshold -
				FLASH_LED_THERMAL_THRESHOLD_MIN) /
				FLASH_LED_THERMAL_DEVIDER;
	}
	rc = qpnp_led_masked_write(led->spmi_dev,
					FLASH_THERMAL_DRATE(led->base),
					FLASH_THERMAL_DERATE_MASK, val);
	if (rc) {
		dev_err(&led->spmi_dev->dev, "Thermal derate reg write failed\n");
		return rc;
	}

	if (!led->pdata->current_ramp_en)
		val = 0x0;
	else {
		val = led->pdata->current_ramp_en << 7;
		val |= led->pdata->ramp_up_step << 3;
		val |= led->pdata->ramp_dn_step;
	}
	rc = qpnp_led_masked_write(led->spmi_dev,
						FLASH_CURRENT_RAMP(led->base),
						FLASH_CURRENT_RAMP_MASK, val);
	if (rc) {
		dev_err(&led->spmi_dev->dev, "Current ramp reg write failed\n");
		return rc;
	}

	if (!led->pdata->vph_pwr_droop_en)
		val = 0x0;
	else {
		val = led->pdata->vph_pwr_droop_en << 7;
		val |= ((led->pdata->vph_pwr_droop_threshold -
				FLASH_LED_VPH_DROOP_THRESHOLD_MIN_MV) /
				FLASH_LED_VPH_DROOP_THRESHOLD_DIVIDER) << 4;
		temp_val =
			qpnp_flash_led_get_droop_debounce_time(
				led->pdata->vph_pwr_droop_debounce_time);
		if (temp_val == 0xFF) {
			dev_err(&led->spmi_dev->dev, "Invalid debounce time\n");
			return temp_val;
		}

		val |= temp_val;
	}
	rc = qpnp_led_masked_write(led->spmi_dev,
						FLASH_VPH_PWR_DROOP(led->base),
						FLASH_VPH_PWR_DROOP_MASK, val);
	if (rc) {
		dev_err(&led->spmi_dev->dev, "VPH PWR droop reg write failed\n");
		return rc;
	}

	led->battery_psy = power_supply_get_by_name("battery");
	if (!led->battery_psy) {
		dev_err(&led->spmi_dev->dev,
			"Failed to get battery power supply\n");
		return -EINVAL;
	}

	return 0;
}

static void qpnp_flash_led_delayed_reg_work(struct work_struct *work)
{
	struct flash_node_data *flash_node = container_of(work,
					struct flash_node_data, dwork.work);
	int rc;

	flash_node->boost_regulator = regulator_get(flash_node->cdev.dev,
								"boost");
	if (IS_ERR(flash_node->boost_regulator)) {
		rc = PTR_ERR(flash_node->boost_regulator);
		flash_node->boost_regulator = NULL;
		pr_err("boost regulator get failed\n");
		return;
	}

	return;
}

static int qpnp_flash_led_parse_each_led_dt(struct qpnp_flash_led *led,
					struct flash_node_data *flash_node)
{
	const char *temp_string;
	struct device_node *node = flash_node->cdev.dev->of_node;
	int rc = 0;
	u32 val;

	rc = of_property_read_string(node, "label", &temp_string);
	if (!rc) {
		if (strcmp(temp_string, "flash") == 0)
			flash_node->type = FLASH;
		else if (strcmp(temp_string, "torch") == 0)
			flash_node->type = TORCH;
		else if (strcmp(temp_string, "switch") == 0)
			flash_node->type = SWITCH;
		else if (strcmp(temp_string, "dual_leds") == 0)
			flash_node->type = DUAL_LEDS;
		else {
			dev_err(&led->spmi_dev->dev,
					"Wrong flash LED type\n");
			return -EINVAL;
		}
	} else if (rc < 0) {
		dev_err(&led->spmi_dev->dev,
					"Unable to read flash type\n");
		return rc;
	}

	rc = of_property_read_u32(node, "qcom,current", &val);
	if (!rc) {
		if (val < FLASH_LED_MIN_CURRENT_MA)
			val = FLASH_LED_MIN_CURRENT_MA;
		flash_node->prgm_current = val;
	} else if (rc != -EINVAL) {
		dev_err(&led->spmi_dev->dev,
				"Unable to read current\n");
		return rc;
	}

	rc = of_property_read_u32(node, "qcom,duration", &val);
	if (!rc)
		flash_node->duration = (u16)val;
	else if (rc != -EINVAL) {
		dev_err(&led->spmi_dev->dev, "Unable to read duration\n");
		return rc;
	}

	rc = of_property_read_u32(node, "qcom,id", &val);
	if (!rc)
		flash_node->id = (u8)val;
	else if (rc != -EINVAL) {
		dev_err(&led->spmi_dev->dev, "Unable to read led ID\n");
		return rc;
	}

	switch (led->peripheral_type) {
	case FLASH_SUBTYPE_SINGLE:
		flash_node->trigger = FLASH_LED0_TRIGGER;
		break;
	case FLASH_SUBTYPE_DUAL:
		if (flash_node->id == FLASH_LED_0) {
			flash_node->trigger = FLASH_LED0_TRIGGER;
		} else if (flash_node->id == FLASH_LED_1) {
			flash_node->trigger = FLASH_LED1_TRIGGER;
		} else if (flash_node->id == FLASH_LED_2) {
			flash_node->enable = FLASH_MODULE_ENABLE;
			flash_node->trigger = FLASH_LED0_TRIGGER|FLASH_LED1_TRIGGER;
		}
		break;
	default:
		dev_err(&led->spmi_dev->dev, "Invalid peripheral type\n");
	}

	if (of_find_property(node, "boost-supply", NULL)) {
		INIT_DELAYED_WORK(&flash_node->dwork,
					qpnp_flash_led_delayed_reg_work);

		flash_node->boost_regulator =
				regulator_get(flash_node->cdev.dev, "boost");
		if (!flash_node->boost_regulator ||
				IS_ERR(flash_node->boost_regulator))
			schedule_delayed_work(&flash_node->dwork,
					FLASH_BOOST_REGULATOR_PROBE_DELAY_MS);

		rc = of_property_read_u32(node, "boost-voltage-max", &val);
		if (!rc)
			flash_node->boost_voltage_max = val;
		else {
			dev_err(&led->spmi_dev->dev,
			"Unable to read maximum boost regulator voltage\n");
			goto error_regulator_config;
		}
	}

	return rc;

error_regulator_config:
	regulator_put(flash_node->boost_regulator);
	return rc;
}

static int qpnp_flash_led_parse_common_dt(
				struct qpnp_flash_led *led,
						struct device_node *node)
{
	int rc;
	u32 val, temp_val;
	const char *temp;

	led->pdata->headroom = FLASH_LED_HEADROOM_DEFAULT_MV;
	rc = of_property_read_u32(node, "qcom,headroom", &val);
	if (!rc)
		led->pdata->headroom = (u16)val;
	else if (rc != -EINVAL) {
		dev_err(&led->spmi_dev->dev, "Unable to read headroom\n");
		return rc;
	}

	led->pdata->startup_dly = FLASH_LED_STARTUP_DELAY_DEFAULT_US;
	rc = of_property_read_u32(node, "qcom,startup-dly", &val);
	if (!rc)
		led->pdata->startup_dly = (u8)val;
	else if (rc != -EINVAL) {
		dev_err(&led->spmi_dev->dev,
					"Unable to read startup delay\n");
		return rc;
	}

	led->pdata->clamp_current = FLASH_LED_CLAMP_CURRENT_DEFAULT_MA;
	rc = of_property_read_u32(node, "qcom,clamp-current", &val);
	if (!rc) {
		if (val < FLASH_LED_MIN_CURRENT_MA)
			val = FLASH_LED_MIN_CURRENT_MA;
		led->pdata->clamp_current = (u16)val;
	} else if (rc != -EINVAL) {
		dev_err(&led->spmi_dev->dev,
					"Unable to read clamp current\n");
		return rc;
	}

	led->pdata->pmic_charger_support =
			of_property_read_bool(node,
						"qcom,pmic-charger-support");

	led->pdata->self_check_en =
			of_property_read_bool(node, "qcom,self-check-enabled");

	led->pdata->thermal_derate_en =
			of_property_read_bool(node,
						"qcom,thermal-derate-enabled");

	if (led->pdata->thermal_derate_en) {
		led->pdata->thermal_derate_rate =
				FLASH_LED_THERMAL_DERATE_RATE_DEFAULT_PERCENT;
		rc = of_property_read_string(node, "qcom,thermal-derate-rate",
									&temp);
		if (!rc) {
			temp_val =
				qpnp_flash_led_get_thermal_derate_rate(temp);
			if (temp_val < 0) {
				dev_err(&led->spmi_dev->dev,
					"Invalid thermal derate rate\n");
				return -EINVAL;
			}

			led->pdata->thermal_derate_rate = (u8)temp_val;
		} else {
			dev_err(&led->spmi_dev->dev,
				"Unable to read thermal derate rate\n");
			return -EINVAL;
		}

		led->pdata->thermal_derate_threshold =
				FLASH_LED_THERMAL_DERATE_THRESHOLD_DEFAULT_C;
		rc = of_property_read_u32(node, "qcom,thermal-derate-threshold",
									&val);
		if (!rc)
			led->pdata->thermal_derate_threshold = (u8)val;
		else if (rc != -EINVAL) {
			dev_err(&led->spmi_dev->dev,
				"Unable to read thermal derate threshold\n");
			return rc;
		}
	}

	led->pdata->current_ramp_en =
			of_property_read_bool(node,
						"qcom,current-ramp-enabled");
	if (led->pdata->current_ramp_en) {
		led->pdata->ramp_up_step = FLASH_LED_RAMP_UP_STEP_DEFAULT_US;
		rc = of_property_read_string(node, "qcom,ramp_up_step", &temp);
		if (!rc) {
			temp_val = qpnp_flash_led_get_ramp_step(temp);
			if (temp_val < 0) {
				dev_err(&led->spmi_dev->dev,
					"Invalid ramp up step values\n");
				return -EINVAL;
			}
			led->pdata->ramp_up_step = (u8)temp_val;
		} else if (rc != -EINVAL) {
			dev_err(&led->spmi_dev->dev,
					"Unable to read ramp up steps\n");
			return rc;
		}

		led->pdata->ramp_dn_step = FLASH_LED_RAMP_DN_STEP_DEFAULT_US;
		rc = of_property_read_string(node, "qcom,ramp_dn_step", &temp);
		if (!rc) {
			temp_val = qpnp_flash_led_get_ramp_step(temp);
			if (temp_val < 0) {
				dev_err(&led->spmi_dev->dev,
					"Invalid ramp down step values\n");
				return rc;
			}
			led->pdata->ramp_dn_step = (u8)temp_val;
		} else if (rc != -EINVAL) {
			dev_err(&led->spmi_dev->dev,
					"Unable to read ramp down steps\n");
			return rc;
		}
	}

	led->pdata->vph_pwr_droop_en = of_property_read_bool(node,
						"qcom,vph-pwr-droop-enabled");
	if (led->pdata->vph_pwr_droop_en) {
		led->pdata->vph_pwr_droop_threshold =
				FLASH_LED_VPH_PWR_DROOP_THRESHOLD_DEFAULT_MV;
		rc = of_property_read_u32(node,
					"qcom,vph-pwr-droop-threshold", &val);
		if (!rc) {
			led->pdata->vph_pwr_droop_threshold = (u16)val;
		} else if (rc != -EINVAL) {
			dev_err(&led->spmi_dev->dev,
				"Unable to read VPH PWR droop threshold\n");
			return rc;
		}

		led->pdata->vph_pwr_droop_debounce_time =
			FLASH_LED_VPH_PWR_DROOP_DEBOUNCE_TIME_DEFAULT_US;
		rc = of_property_read_u32(node,
				"qcom,vph-pwr-droop-debounce-time", &val);
		if (!rc)
			led->pdata->vph_pwr_droop_debounce_time = (u8)val;
		else if (rc != -EINVAL) {
			dev_err(&led->spmi_dev->dev,
				"Unable to read VPH PWR droop debounce time\n");
			return rc;
		}
	}

	led->pdata->hdrm_sns_ch0_en = of_property_read_bool(node,
						"qcom,headroom-sense-ch0-enabled");

	led->pdata->hdrm_sns_ch1_en = of_property_read_bool(node,
						"qcom,headroom-sense-ch1-enabled");

	led->pdata->power_detect_en = of_property_read_bool(node,
						"qcom,power-detect-enabled");

	led->pdata->mask3_en = of_property_read_bool(node,
						"qcom,otst2-module-enabled");

	led->pdata->follow_rb_disable = of_property_read_bool(node,
						"qcom,follow-otst2-rb-disabled");

	led->pdata->die_current_derate_en = of_property_read_bool(node,
					"qcom,die-current-derate-enabled");
	if (led->pdata->die_current_derate_en) {
		led->vadc_dev = qpnp_get_vadc(&led->spmi_dev->dev,
							"die-temp");
		if (IS_ERR(led->vadc_dev)) {
			pr_err("VADC channel property Missing\n");
			return -EINVAL;
		}

		if (of_find_property(node, "qcom,die-temp-threshold",
				&led->pdata->temp_threshold_num)) {

			if (led->pdata->temp_threshold_num > 0) {
				led->pdata->die_temp_threshold_degc =
				devm_kzalloc(&led->spmi_dev->dev,
						led->pdata->temp_threshold_num,
						GFP_KERNEL);

				if (led->pdata->die_temp_threshold_degc
								== NULL) {
					dev_err(&led->spmi_dev->dev,
					"failed to allocate die temp array\n");
					return -ENOMEM;
				}
				led->pdata->temp_threshold_num /=
							sizeof(unsigned int);

				rc = of_property_read_u32_array(node,
						"qcom,die-temp-threshold",
				led->pdata->die_temp_threshold_degc,
						led->pdata->temp_threshold_num);
				if (rc) {
					dev_err(&led->spmi_dev->dev,
					"couldn't read temp threshold rc=%d\n",
								rc);
					return rc;
				}
			}
		}

		if (of_find_property(node, "qcom,die-temp-derate-current",
					&led->pdata->temp_derate_curr_num)) {
			if (led->pdata->temp_derate_curr_num > 0) {
				led->pdata->die_temp_derate_curr_ma =
					devm_kzalloc(&led->spmi_dev->dev,
					led->pdata->temp_derate_curr_num,
					GFP_KERNEL);
				if (led->pdata->die_temp_derate_curr_ma
								== NULL) {
					dev_err(&led->spmi_dev->dev,
						"failed to allocate die derate current array\n");
					return -ENOMEM;
				}
				led->pdata->temp_derate_curr_num /=
						sizeof(unsigned int);

				rc = of_property_read_u32_array(node,
						"qcom,die-temp-derate-current",
				led->pdata->die_temp_derate_curr_ma,
				led->pdata->temp_derate_curr_num);
				if (rc) {
					dev_err(&led->spmi_dev->dev,
					"couldn't read temp limits rc =%d\n",
								rc);
					return rc;
				}
			}
		}
		if (led->pdata->temp_threshold_num !=
					led->pdata->temp_derate_curr_num) {
			pr_err("Both array size are not same\n");
			return -EINVAL;
		}
	}

	led->pinctrl = devm_pinctrl_get(&led->spmi_dev->dev);
	if (IS_ERR_OR_NULL(led->pinctrl)) {
		dev_err(&led->spmi_dev->dev,
				"Unable to acquire pinctrl\n");
		led->pinctrl = NULL;
		return 0;
	} else {
		led->gpio_state_active =
		pinctrl_lookup_state(led->pinctrl, "flash_led_enable");
		if (IS_ERR_OR_NULL(led->gpio_state_active)) {
			dev_err(&led->spmi_dev->dev,
				"Can not lookup LED active state\n");
			devm_pinctrl_put(led->pinctrl);
			led->pinctrl = NULL;
			return PTR_ERR(led->gpio_state_active);
		}
		led->gpio_state_suspend =
		pinctrl_lookup_state(led->pinctrl, "flash_led_disable");
		if (IS_ERR_OR_NULL(led->gpio_state_suspend)) {
			dev_err(&led->spmi_dev->dev,
				"Can not lookup LED disable state\n");
			devm_pinctrl_put(led->pinctrl);
			led->pinctrl = NULL;
			return PTR_ERR(led->gpio_state_suspend);
		}
	}

	return 0;
}

static int qpnp_flash_led_probe(struct spmi_device *spmi)
{
	struct qpnp_flash_led *led;
	struct resource *flash_resource;
	struct device_node *node, *temp;
	struct dentry *root, *file;
	int rc, i = 0, j = 0, num_leds = 0;
	u32 val;

	FLT_INFO_LOG("%s: ++\n", __func__);

	node = spmi->dev.of_node;
	if (node == NULL) {
		dev_info(&spmi->dev, "No flash device defined\n");
		return -ENODEV;
	}

	flash_resource = spmi_get_resource(spmi, 0, IORESOURCE_MEM, 0);
	if (!flash_resource) {
		dev_err(&spmi->dev, "Unable to get flash LED base address\n");
		return -EINVAL;
	}

	led = devm_kzalloc(&spmi->dev, sizeof(struct qpnp_flash_led),
								GFP_KERNEL);
	if (!led) {
		dev_err(&spmi->dev,
			"Unable to allocate memory for flash LED\n");
		return -ENOMEM;
	}

	led->base = flash_resource->start;
	led->spmi_dev = spmi;
	led->current_addr = FLASH_LED0_CURRENT(led->base);
	led->current2_addr = FLASH_LED1_CURRENT(led->base);

	led->pdata = devm_kzalloc(&spmi->dev,
			sizeof(struct flash_led_platform_data), GFP_KERNEL);
	if (!led->pdata) {
		dev_err(&spmi->dev,
			"Unable to allocate memory for platform data\n");
		return -ENOMEM;
	}

	led->peripheral_type =
			(u8)qpnp_flash_led_get_peripheral_type(led);
	if (led->peripheral_type < 0) {
		dev_err(&spmi->dev, "Failed to get peripheral type\n");
		return rc;
	}

	rc = qpnp_flash_led_parse_common_dt(led, node);
	if (rc) {
		dev_err(&spmi->dev,
			"Failed to get common config for flash LEDs\n");
		return rc;
	}

	rc = qpnp_flash_led_init_settings(led);
	if (rc) {
		dev_err(&spmi->dev, "Failed to initialize flash LED\n");
		return rc;
	}

	temp = NULL;
	while ((temp = of_get_next_child(node, temp)))
		num_leds++;

	if (!num_leds)
		return -ECHILD;

	led->flash_node = devm_kzalloc(&spmi->dev,
			(sizeof(struct flash_node_data) * num_leds),
			GFP_KERNEL);
	if (!led->flash_node) {
		dev_err(&spmi->dev, "Unable to allocate memory\n");
		return -ENOMEM;
	}


	INIT_DELAYED_WORK(&pmi8950_delayed_work, flashlight_turn_off_work);
	pmi8950_work_queue = create_singlethread_workqueue("pmi8950_wq");
	if (!pmi8950_work_queue)
		goto err_create_pmi8950_work_queue;

	htc_flash_main = &pmi8950_flash_mode;
	htc_torch_main = &pmi8950_torch_mode;

	mutex_init(&led->flash_led_lock);

	led->ordered_workq = alloc_ordered_workqueue("flash_led_workqueue", 0);
	if (!led->ordered_workq) {
		dev_err(&spmi->dev,
			"Failed to allocate ordered workqueue\n");
		return -ENOMEM;
	}

	for_each_child_of_node(node, temp) {
		led->flash_node[i].cdev.brightness_set =
						qpnp_flash_led_brightness_set;
		led->flash_node[i].cdev.brightness_get =
						qpnp_flash_led_brightness_get;
		led->flash_node[i].spmi_dev = spmi;

		INIT_WORK(&led->flash_node[i].work, qpnp_flash_led_work);
		rc = of_property_read_string(temp, "qcom,led-name",
						&led->flash_node[i].cdev.name);
		if (rc < 0) {
			dev_err(&led->spmi_dev->dev,
					"Unable to read flash name\n");
			return rc;
		}

		rc = of_property_read_string(temp, "qcom,default-led-trigger",
				&led->flash_node[i].cdev.default_trigger);
		if (rc < 0) {
			dev_err(&led->spmi_dev->dev,
					"Unable to read trigger name\n");
			return rc;
		}

		rc = of_property_read_u32(temp, "qcom,max-current", &val);
		if (!rc) {
			if (val < FLASH_LED_MIN_CURRENT_MA)
				val = FLASH_LED_MIN_CURRENT_MA;
			led->flash_node[i].max_current = (u16)val;
			led->flash_node[i].cdev.max_brightness = val;
		} else {
			dev_err(&led->spmi_dev->dev,
					"Unable to read max current\n");
			return rc;
		}
		rc = led_classdev_register(&spmi->dev,
						&led->flash_node[i].cdev);
		if (rc) {
			dev_err(&spmi->dev, "Unable to register led\n");
			goto error_led_register;
		}

		led->flash_node[i].cdev.dev->of_node = temp;

		rc = qpnp_flash_led_parse_each_led_dt(led, &led->flash_node[i]);
		if (rc) {
			dev_err(&spmi->dev,
				"Failed to parse config for each LED\n");
			goto error_led_register;
		}

		for (j = 0; j < ARRAY_SIZE(qpnp_flash_led_attrs); j++) {
			rc =
			sysfs_create_file(&led->flash_node[i].cdev.dev->kobj,
					&qpnp_flash_led_attrs[j].attr);
			if (rc)
				goto error_led_register;
		}

		i++;
	}

	led->num_leds = i;

	root = debugfs_create_dir("flashLED", NULL);
	if (IS_ERR_OR_NULL(root)) {
		pr_err("Error creating top level directory err%ld",
			(long)root);
		if (PTR_ERR(root) == -ENODEV)
			pr_err("debugfs is not enabled in kernel");
		goto error_debugfs_create;
	}

	led->dbgfs_root = root;
	file = debugfs_create_file("enable_debug", S_IRUSR | S_IWUSR, root,
					led, &flash_led_dfs_dbg_feature_fops);
	if (!file) {
		pr_err("error creating 'enable_debug' entry\n");
		goto error_debugfs_create;
	}

	file = debugfs_create_file("latched", S_IRUSR | S_IWUSR, root, led,
					&flash_led_dfs_latched_reg_fops);
	if (!file) {
		pr_err("error creating 'latched' entry\n");
		goto error_debugfs_create;
	}

	file = debugfs_create_file("strobe", S_IRUSR | S_IWUSR, root, led,
					&flash_led_dfs_strobe_reg_fops);
	if (!file) {
		pr_err("error creating 'strobe' entry\n");
		goto error_debugfs_create;
	}

	this_led = led;

	dev_set_drvdata(&spmi->dev, led);

	FLT_INFO_LOG("%s: --\n", __func__);
	return 0;


error_debugfs_create:
	debugfs_remove_recursive(root);
error_led_register:
	for (; i >= 0; i--) {
		for (; j >= 0; j--)
			sysfs_remove_file(&led->flash_node[i].cdev.dev->kobj,
						&qpnp_flash_led_attrs[j].attr);
		j = ARRAY_SIZE(qpnp_flash_led_attrs) - 1;
		led_classdev_unregister(&led->flash_node[i].cdev);
	}
err_create_pmi8950_work_queue:
	kfree(led);
	mutex_destroy(&led->flash_led_lock);
	destroy_workqueue(led->ordered_workq);

	return rc;
}

static int qpnp_flash_led_remove(struct spmi_device *spmi)
{
	struct qpnp_flash_led *led  = dev_get_drvdata(&spmi->dev);
	int i, j;

	for (i = led->num_leds - 1; i >= 0; i--) {
		if (led->flash_node[i].boost_regulator)
			regulator_put(led->flash_node[i].boost_regulator);
		for (j = 0; j < ARRAY_SIZE(qpnp_flash_led_attrs); j++)
			sysfs_remove_file(&led->flash_node[i].cdev.dev->kobj,
						&qpnp_flash_led_attrs[j].attr);
		led_classdev_unregister(&led->flash_node[i].cdev);
	}
	debugfs_remove_recursive(led->dbgfs_root);
	mutex_destroy(&led->flash_led_lock);
	destroy_workqueue(led->ordered_workq);

	return 0;
}

static struct of_device_id spmi_match_table[] = {
	{ .compatible = "qcom,qpnp-flash-led",},
	{ },
};

static struct spmi_driver qpnp_flash_led_driver = {
	.driver		= {
		.name = "qcom,qpnp-flash-led",
		.of_match_table = spmi_match_table,
	},
	.probe		= qpnp_flash_led_probe,
	.remove		= qpnp_flash_led_remove,
};

static int __init qpnp_flash_led_init(void)
{
	return spmi_driver_register(&qpnp_flash_led_driver);
}
late_initcall(qpnp_flash_led_init);

static void __exit qpnp_flash_led_exit(void)
{
	spmi_driver_unregister(&qpnp_flash_led_driver);
}
module_exit(qpnp_flash_led_exit);

MODULE_DESCRIPTION("QPNP Flash LED driver");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS("leds:leds-qpnp-flash");
/*
 * FPC1020 Fingerprint sensor device driver
 *
 * This driver will control the platform resources that the FPC fingerprint
 * sensor needs to operate. The major things are probing the sensor to check
 * that it is actually connected and let the Kernel know this and with that also
 * enabling and disabling of regulators, enabling and disabling of platform
 * clocks, controlling GPIOs such as SPI chip select, sensor reset line, sensor
 * IRQ line, MISO and MOSI lines.
 *
 * The driver will expose most of its available functionality in sysfs which
 * enables dynamic control of these features from eg. a user space process.
 *
 * The sensor's IRQ events will be pushed to Kernel's event handling system and
 * are exposed in the drivers event node. This makes it possible for a user
 * space process to poll the input node and receive IRQ events easily. Usually
 * this node is available under /dev/input/eventX where 'X' is a number given by
 * the event system. A user space process will need to traverse all the event
 * nodes and ask for its parent's name (through EVIOCGNAME) which should match
 * the value in device tree named input-device-name.
 *
 * This driver will NOT send any SPI commands to the sensor it only controls the
 * electrical parts.
 *
 *
 * Copyright (c) 2015 Fingerprint Cards AB <tech@fingerprints.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License Version 2
 * as published by the Free Software Foundation.
 */

#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/gpio.h>
#include <linux/input.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/of.h>
#include <linux/of_gpio.h>
#include <soc/qcom/scm.h>
#include <linux/pinctrl/consumer.h>
#include <linux/platform_device.h>
#include <linux/input/mt.h>
#include <linux/irq.h>
#include <linux/io.h>
#include <linux/async.h>
#include <linux/spi/spi.h>
#include <linux/wakelock.h>
#include <linux/rtc.h>

#ifdef CONFIG_FB
#include <linux/notifier.h>
#include <linux/fb.h>
#endif //CONFIG_FB

#include <linux/regulator/consumer.h>

#ifdef CONFIG_FPC_HTC_DISABLE_CHARGING
#include <linux/power/htc_battery_common.h>
#endif //CONFIG_FPC_HTC_DISABLE_CHARGING

#ifdef CONFIG_FB
static int fb_notifier_callback(struct notifier_block *self,
				 unsigned long event, void *data);
#endif

#define FPC1020_RESET_LOW_US 1000
#define FPC1020_RESET_HIGH1_US 100
#define FPC1020_RESET_HIGH2_US 1250

/* SW15 ++ */
#define FPC_TTW_HOLD_TIME 500
/* SW15 -- */

#define DEBUG

#ifdef dev_dbg
#undef dev_dbg
#endif
#define dev_dbg(dev, format, arg...) do { if (1) \
                                        dev_info(dev,format, ##arg); \
                                        }while(0)

static const char * const pctl_names[] = {
	"fpc1020_reset_reset",
	"fpc1020_reset_active",
	"fpc1020_irq_active",
	"fpc1020_spi_active",
	"fpc1020_spi_suspend",
	"fpc1020_cs_high"
};
struct vreg_config {
	char *name;
	unsigned long vmin;
	unsigned long vmax;
	int ua_load;
};

/* SW15 ++ */
static const struct vreg_config const vreg_conf[] = {
	{ "vdd_ana", 1800000UL, 1800000UL, 6000, },
	{ "vcc_spi", 1800000UL, 1800000UL, 10, },
	{ "vdd_io", 1800000UL, 1800000UL, 6000, },
};
/* SW15 -- */

struct fpc1020_data {
	struct device *dev;
	struct spi_device *spi;
	struct pinctrl *fingerprint_pinctrl;
#ifdef CONFIG_FB
	struct notifier_block fb_notifier;
#endif
	struct pinctrl_state *pinctrl_state[ARRAY_SIZE(pctl_names)];
	struct clk *iface_clk;
	struct clk *core_clk;
	struct regulator *vreg[ARRAY_SIZE(vreg_conf)]; /* SW15 */
    struct wake_lock ttw_wl; /* SW15 */
	int irq_gpio;
	int cs0_gpio; /* SW15 */
	int cs1_gpio; /* SW15 */
	int rst_gpio;
	struct input_dev *idev;
	struct regulator *regulator_l22;
	int irq_num;
	int qup_id; /* SW15 */
	char idev_name[32];
	int event_type;
	int event_code;
	struct mutex lock;
	bool prepared;
	bool wakeup_enabled; /* SW15 */
#ifdef CONFIG_FB
	int blank;
#endif
	bool irq_enabled; /* Add for En/Disable IRQ */
};

/* SW15 ++ */
/*
static int vreg_setup(struct fpc1020_data *fpc1020, const char *name,
	bool enable)
{
	size_t i;
	int rc;
	struct regulator *vreg;
	struct device *dev = fpc1020->dev;

	for (i = 0; i < ARRAY_SIZE(fpc1020->vreg); i++) {
		const char *n = vreg_conf[i].name;
		if (!strncmp(n, name, strlen(n)))
			goto found;
	}
	dev_err(dev, "Regulator %s not found\n", name);
	return -EINVAL;
found:
	vreg = fpc1020->vreg[i];
	if (enable) {
		if (!vreg) {
			vreg = regulator_get(dev, name);
			if (!vreg) {
				dev_err(dev, "Unable to get  %s\n", name);
				return -ENODEV;
			}
		}
		if (regulator_count_voltages(vreg) > 0) {
			rc = regulator_set_voltage(vreg, vreg_conf[i].vmin,
					vreg_conf[i].vmax);
			if (rc)
				dev_err(dev,
					"Unable to set voltage on %s, %d\n",
					name, rc);
		}
		rc = regulator_set_optimum_mode(vreg, vreg_conf[i].ua_load);
		if (rc < 0)
			dev_err(dev, "Unable to set current on %s, %d\n",
					name, rc);
		rc = regulator_enable(vreg);
		if (rc) {
			dev_err(dev, "error enabling %s: %d\n", name, rc);
			regulator_put(vreg);
			vreg = NULL;
		}
		fpc1020->vreg[i] = vreg;
	} else {
		if (vreg) {
			if (regulator_is_enabled(vreg)) {
				regulator_disable(vreg);
				dev_dbg(dev, "disabled %s\n", name);
			}
			regulator_put(vreg);
			fpc1020->vreg[i] = NULL;
		}
		rc = 0;
	}
	return rc;
}
*/
/**
 * Prepare or unprepare the SPI master that we are soon to transfer something
 * over SPI.
 *
 * Please see Linux Kernel manual for SPI master methods for more information.
 *
 * @see Linux SPI master methods
 */
/*
static int spi_set_fabric(struct fpc1020_data *fpc1020, bool active)
{
	struct spi_master *master = fpc1020->spi->master;
	int rc = active ?
		master->prepare_transfer_hardware(master) :
		master->unprepare_transfer_hardware(master);
	if (rc)
		dev_err(fpc1020->dev, "%s: rc %d\n", __func__, rc);
	else
		dev_dbg(fpc1020->dev, "%s: %d ok\n", __func__, active);
	return rc;
}
*/
/**
 * Changes ownership of SPI transfers from TEE to REE side or vice versa.
 *
 * SPI transfers can be owned only by one of TEE or REE side at any given time.
 * This can be changed dynamically if needed but of course that needs support
 * from underlaying layers. This function will transfer the ownership from REE
 * to TEE or vice versa.
 *
 * If REE side uses the SPI master when TEE owns the pipe or vice versa the
 * system will most likely crash dump.
 *
 * If available this should be set at boot time to eg. TEE side and not
 * dynamically as that will increase the security of the system. This however
 * implies that there are no other SPI slaves connected that should be handled
 * from REE side.
 *
 * @see SET_PIPE_OWNERSHIP
 */
/*
static int set_pipe_ownership(struct fpc1020_data *fpc1020, bool to_tz)
{
	int rc;
	const u32 TZ_BLSP_MODIFY_OWNERSHIP_ID = 3;
	const u32 TZBSP_APSS_ID = 1;
	const u32 TZBSP_TZ_ID = 3;
	struct scm_desc desc = {
		.arginfo = SCM_ARGS(2),
		.args[0] = fpc1020->qup_id,
		.args[1] = to_tz ? TZBSP_TZ_ID : TZBSP_APSS_ID,
	};

	rc = scm_call2(SCM_SIP_FNID(SCM_SVC_TZ, TZ_BLSP_MODIFY_OWNERSHIP_ID),
		&desc);

	if (rc || desc.ret[0]) {
		dev_err(fpc1020->dev, "%s: scm_call2: responce %llu, rc %d\n",
				__func__, desc.ret[0], rc);
		return -EINVAL;
	}
	dev_dbg(fpc1020->dev, "%s: scm_call2: ok\n", __func__);
	return 0;
}
*/
/*
static int set_clks(struct fpc1020_data *fpc1020, bool enable)
{
	int rc;

	if (enable) {
		rc = clk_set_rate(fpc1020->core_clk,
				fpc1020->spi->max_speed_hz);
		if (rc) {
			dev_err(fpc1020->dev,
					"%s: Error setting clk_rate: %u, %d\n",
					__func__, fpc1020->spi->max_speed_hz,
					rc);
			return rc;
		}
		rc = clk_prepare_enable(fpc1020->core_clk);
		if (rc) {
			dev_err(fpc1020->dev,
					"%s: Error enabling core clk: %d\n",
					__func__, rc);
			return rc;
		}
		rc = clk_prepare_enable(fpc1020->iface_clk);
		if (rc) {
			dev_err(fpc1020->dev,
					"%s: Error enabling iface clk: %d\n",
					__func__, rc);
			clk_disable_unprepare(fpc1020->core_clk);
			return rc;
		}
		dev_dbg(fpc1020->dev, "%s ok. clk rate %u hz\n", __func__,
				fpc1020->spi->max_speed_hz);
	} else {
		clk_disable_unprepare(fpc1020->iface_clk);
		clk_disable_unprepare(fpc1020->core_clk);
		rc = 0;
	}
	return rc;
}
*/
/**
 * sysfs node handler to support dynamic change of SPI transfers' ownership
 * between TEE and REE side.
 *
 * An owner in this context is REE or TEE.
 *
 * @see set_pipe_ownership
 * @see SET_PIPE_OWNERSHIP
 */
/*
static ssize_t spi_owner_set(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	struct  fpc1020_data *fpc1020 = dev_get_drvdata(dev);
	int rc;
	bool to_tz;

	if (!strncmp(buf, "tz", strlen("tz")))
		to_tz = true;
	else if (!strncmp(buf, "app", strlen("app")))
		to_tz = false;
	else
		return -EINVAL;

	rc = set_pipe_ownership(fpc1020, to_tz);
	return rc ? rc : count;
}
static DEVICE_ATTR(spi_owner, S_IWUSR, NULL, spi_owner_set);
*/
/*
static ssize_t clk_enable_set(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	struct  fpc1020_data *fpc1020 = dev_get_drvdata(dev);
	int rc = set_clks(fpc1020, *buf == '1');
	return rc ? rc : count;
}
static DEVICE_ATTR(clk_enable, S_IWUSR, NULL, clk_enable_set);
*/
/**
 * Will indicate to the SPI driver that a message is soon to be delivered over
 * it.
 *
 * Exactly what fabric resources are requested is up to the SPI device driver.
 *
 * @see spi_set_fabric
 */
/*
static ssize_t fabric_vote_set(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	struct  fpc1020_data *fpc1020 = dev_get_drvdata(dev);
	int rc = spi_set_fabric(fpc1020, *buf == '1');
	return rc ? rc : count;
}
static DEVICE_ATTR(fabric_vote, S_IWUSR, NULL, fabric_vote_set);
*/
/*
static ssize_t spi_bus_lock_set(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	struct  fpc1020_data *fpc1020 = dev_get_drvdata(dev);

	if (!strncmp(buf, "lock", strlen("lock")))
		spi_bus_lock(fpc1020->spi->master);
	else if (!strncmp(buf, "unlock", strlen("unlock")))
		spi_bus_unlock(fpc1020->spi->master);
	else
		return -EINVAL;
	return count;
}
static DEVICE_ATTR(bus_lock, S_IWUSR, NULL, spi_bus_lock_set);
*/

/*
static ssize_t regulator_enable_set(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	struct  fpc1020_data *fpc1020 = dev_get_drvdata(dev);
	char op;
	char name[16];
	int rc;
	bool enable;

	if (2 != sscanf(buf, "%15s,%c", name, &op))
		return -EINVAL;
	if (op == 'e')
		enable = true;
	else if (op == 'd')
		enable = false;
	else
		return -EINVAL;
	rc = vreg_setup(fpc1020, name, enable);
	return rc ? rc : count;
}
static DEVICE_ATTR(regulator_enable, S_IWUSR, NULL, regulator_enable_set);
*/
/* SW15 -- */

static int select_pin_ctl(struct fpc1020_data *fpc1020, const char *name)
{
	size_t i;
	int rc;
	struct device *dev = fpc1020->dev;
	for (i = 0; i < ARRAY_SIZE(fpc1020->pinctrl_state); i++) {
		const char *n = pctl_names[i];
		if (!strncmp(n, name, strlen(n))) {
			rc = pinctrl_select_state(fpc1020->fingerprint_pinctrl,
					fpc1020->pinctrl_state[i]);
			if (rc)
				dev_err(dev, "cannot select '%s'\n", name);
			else
				dev_dbg(dev, "Selected '%s'\n", name);
			goto exit;
		}
	}
	rc = -EINVAL;
	dev_err(dev, "%s:'%s' not found\n", __func__, name);
exit:
	return rc;
}

static int device_prepare(struct  fpc1020_data *fpc1020, bool enable)
{
	int rc = 0;
	int retval;
	struct device *dev = fpc1020->dev;
	mutex_lock(&fpc1020->lock);
	if (enable && !fpc1020->prepared) {
		fpc1020->prepared = true;
		select_pin_ctl(fpc1020, "fpc1020_reset_reset");

		usleep_range(100, 1000);
		//Power-on sequence adjustment
		retval = regulator_enable(fpc1020->regulator_l22);
		if (retval) {
			printk("[fp][FPC]Fail to enable l22 regulator\n");
			rc = retval;
		}else{
			dev_dbg(dev, "Enable 1V8 Power Pin\n");
		}
		(void)select_pin_ctl(fpc1020, "fpc1020_cs_high");
		usleep_range(300,500);
		(void)select_pin_ctl(fpc1020, "fpc1020_reset_active");
		usleep_range(1300, 1500);

	} else if (!enable && fpc1020->prepared) {
		rc = 0;
		(void)select_pin_ctl(fpc1020, "fpc1020_reset_reset");
		usleep_range(100, 1000);

		fpc1020->prepared = false;
	} else {
		rc = 0;
	}
	mutex_unlock(&fpc1020->lock);
	return rc;
}

/* SW15 ++ */
/**
 * sysfs node for controlling whether the driver is allowed
 * to wake up the platform on interrupt.
 */
static ssize_t wakeup_enable_set(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	struct  fpc1020_data *fpc1020 = dev_get_drvdata(dev);

	if (!strncmp(buf, "enable", strlen("enable")))
	{
		fpc1020->wakeup_enabled = true;
		smp_wmb();
	}
	else if (!strncmp(buf, "disable", strlen("disable")))
	{
		fpc1020->wakeup_enabled = false;
		smp_wmb();
	}
	else
		return -EINVAL;

	return count;
}
static DEVICE_ATTR(wakeup_enable, S_IWUGO, NULL, wakeup_enable_set);


/**
 * sysfs node for sending event to make the system interactive,
 * i.e. waking up
 */
static ssize_t do_wakeup_set(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	struct  fpc1020_data *fpc1020 = dev_get_drvdata(dev);

	if( count > 0 )
	{
		/* Sending power key event creates a toggling
		   effect that may be desired. It could be
		   replaced by another event such as KEY_WAKEUP. */
		input_report_key(fpc1020->idev, KEY_POWER, 1);
		input_report_key(fpc1020->idev, KEY_POWER, 0);
		input_sync(fpc1020->idev);
	}
	else
	{
		return -EINVAL;
	}

	return count;
}
static DEVICE_ATTR(do_wakeup, S_IWUGO, NULL, do_wakeup_set);

/* SW15 -- */
#ifdef CONFIG_FB
static ssize_t blank_state_set(struct device *dev,
                                struct device_attribute *attr, const char *buf, size_t count)
{
	struct  fpc1020_data *fpc1020 = dev_get_drvdata(dev);
	int ret, state;

	ret = sscanf(buf, "%d", &state);

	if (ret != 1)
		return -EINVAL;
	fpc1020->blank = state;

	return count;
}
static ssize_t blank_state_show(struct device *dev,
                                struct device_attribute *attr, char *buf)
{
	struct fpc1020_data *fpc1020 = dev_get_drvdata(dev);

	return sprintf(buf, "%d\n", fpc1020->blank);
}
static DEVICE_ATTR(blank_state, S_IRUGO | S_IWUGO, blank_state_show, blank_state_set);
#endif

/* ----------------------------------------------------------------------------------- */
/* Add this attribute to enbale/disable IRQ */
static int fpc1020_irq_enable(struct fpc1020_data *fpc1020, bool enable)
{
    int ret = 0;
    int irq_gpio_level;
    irq_gpio_level = gpio_get_value(fpc1020->irq_gpio);

    pr_info("%s+ en:%d, level:%d\n", __func__, enable, irq_gpio_level);

    if (enable)
    {
        fpc1020->irq_enabled = true;
#if 0
        enable_irq(gpio_to_irq( fpc1020->irq_gpio ));
        enable_irq_wake(gpio_to_irq( fpc1020->irq_gpio ));
#endif
    }
    else
    {
        fpc1020->irq_enabled = false;
#if 0
        if (in_interrupt() || in_irq_handler) {
            disable_irq_nosync(gpio_to_irq( fpc1020->irq_gpio ));
        }
        else {
            disable_irq(gpio_to_irq( fpc1020->irq_gpio ));
        }
        disable_irq_wake(gpio_to_irq( fpc1020->irq_gpio ));
#endif
    }

    pr_info("%s- en:%d, level:%d\n", __func__, enable, irq_gpio_level);

    return ret;
}

static ssize_t irq_enable_set(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	struct  fpc1020_data *fpc1020 = dev_get_drvdata(dev);

	if (!strncmp(buf, "enable", strlen("enable")))
	{
		fpc1020_irq_enable(fpc1020, true);
		smp_wmb();
	}
	else if (!strncmp(buf, "disable", strlen("disable")))
	{
		fpc1020_irq_enable(fpc1020, false);
		smp_wmb();
	}
	else {
		pr_err("%s Invalid parameter\n", __func__);
		return -EINVAL;
	}

	return count;
}

static ssize_t irq_enable_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct fpc1020_data *fpc1020 = dev_get_drvdata(dev);

	return sprintf(buf, "%d\n", (fpc1020->irq_enabled ? 1 : 0));
}
static DEVICE_ATTR(irq_enable, S_IRUGO | S_IWUGO, irq_enable_show, irq_enable_set);
/* ----------------------------------------------------------------------------------- */

/* ----------------------------------------------------------------------------------- */
/* Add this attribute for hal_footprint */
static ssize_t hal_footprint_set(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
    struct timespec ts;
    struct rtc_time tm;

    //get current time
    getnstimeofday(&ts);
    rtc_time_to_tm(ts.tv_sec, &tm);

    pr_info("fpc footprint:%s at (%02d-%02d %02d:%02d:%02d.%03lu)\n", buf,
        tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, ts.tv_nsec/1000000);

    return count;
}
static DEVICE_ATTR(hal_footprint, S_IWUGO, NULL, hal_footprint_set);
/* ----------------------------------------------------------------------------------- */

/* ----------------------------------------------------------------------------------- */
/* Add this attribute to read irq gpio level */
static int read_irq_gpio(struct fpc1020_data *fpc1020)
{
    int irq_gpio;

    irq_gpio = gpio_get_value(fpc1020->irq_gpio);

    return irq_gpio;
}

static ssize_t irq_gpio_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
    struct fpc1020_data *fpc1020 = dev_get_drvdata(dev);
    int irq_gpio = read_irq_gpio(fpc1020);
    pr_info("fpc %s:%d\n", __func__, irq_gpio);

    return sprintf(buf, "%d\n", irq_gpio);
}
static DEVICE_ATTR(irq_gpio, S_IRUGO, irq_gpio_show, NULL);
/* ----------------------------------------------------------------------------------- */

/* ----------------------------------------------------------------------------------- */
static ssize_t disable_charging_set(struct device *dev,
    struct device_attribute *attr, const char *buf, size_t count)
{
    //struct  fpc1020_data *fpc1020 = dev_get_drvdata(dev);

    if (!strncmp(buf, "1", strlen("1")))
    {
#ifdef CONFIG_FPC_HTC_DISABLE_CHARGING
        pr_info("%s: 1\n", __func__);
        htc_battery_charger_switch_internal(DISABLE_PWRSRC_FINGERPRINT);
#endif //CONFIG_FPC_HTC_DISABLE_CHARGING
    }
    else if (!strncmp(buf, "0", strlen("0")))
    {
#ifdef CONFIG_FPC_HTC_DISABLE_CHARGING
        pr_info("%s: 0\n", __func__);
        htc_battery_charger_switch_internal(ENABLE_PWRSRC_FINGERPRINT);
#endif //CONFIG_FPC_HTC_DISABLE_CHARGING
    }
    else
        return -EINVAL;

    return count;
}
static DEVICE_ATTR(disable_charging, S_IWUGO, NULL, disable_charging_set);
/* ----------------------------------------------------------------------------------- */

static struct attribute *attributes[] = {
	&dev_attr_wakeup_enable.attr, /* SW15 */
	&dev_attr_do_wakeup.attr, /* SW15 */
#ifdef CONFIG_FB
	&dev_attr_blank_state.attr,
#endif
	&dev_attr_hal_footprint.attr, /* hal_footprint */
	&dev_attr_irq_gpio.attr, /* irq_gpio */
	&dev_attr_irq_enable.attr, /* irq_enable */
	&dev_attr_disable_charging.attr, /* disable_charging */
	NULL
};

static const struct attribute_group attribute_group = {
	.attrs = attributes,
};

static irqreturn_t fpc1020_irq_handler(int irq, void *handle)
{
	struct fpc1020_data *fpc1020 = handle;
	if (fpc1020->irq_enabled) {
		input_event(fpc1020->idev, EV_MSC, MSC_SCAN, ++fpc1020->irq_num);
	}

	/* SW15 ++ */
	/* Make sure 'wakeup_enabled' is updated before using it
	** since this is interrupt context (other thread...) */
	smp_rmb();

	if (fpc1020->wakeup_enabled ) {
		wake_lock_timeout(&fpc1020->ttw_wl, msecs_to_jiffies(FPC_TTW_HOLD_TIME));
	}
	/* Send irq event and possible wakeup key event */
	/* SW15 -- */

	if (fpc1020->irq_enabled) {
		input_sync(fpc1020->idev);
	}

	dev_dbg(fpc1020->dev, "%s en:%d num:%d\n", __func__, fpc1020->irq_enabled, fpc1020->irq_num);
	return IRQ_HANDLED;
}

static int fpc1020_request_named_gpio(struct fpc1020_data *fpc1020,
		const char *label, int *gpio)
{
	struct device *dev = fpc1020->dev;
	struct device_node *np = dev->of_node;
	int rc = of_get_named_gpio(np, label, 0);
	if (rc < 0) {
		dev_err(dev, "failed to get '%s'\n", label);
		return rc;
	}
	*gpio = rc;
	rc = devm_gpio_request(dev, *gpio, label);
	if (rc) {
		dev_err(dev, "failed to request gpio %d\n", *gpio);
		return rc;
	}
	dev_dbg(dev, "%s %d\n", label, *gpio);
	return 0;
}

static int fpc1020_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	int retval;
	int rc = 0;
	size_t i;
	int irqf;
	struct device_node *np = dev->of_node;
	u32 val;
	struct fpc1020_data *fpc1020 = devm_kzalloc(dev, sizeof(*fpc1020),
			GFP_KERNEL);
	if (!fpc1020) {
		dev_err(dev,
			"failed to allocate memory for struct fpc1020_data\n");
		rc = -ENOMEM;
		goto exit;
	}

	printk("[fp][FPC] fpc1020_probe+++\n");

	fpc1020->dev = dev;
	dev_set_drvdata(dev, fpc1020);

	if (!np) {
		dev_err(dev, "no of node found\n");
		rc = -EINVAL;
		goto exit;
	}

	rc = fpc1020_request_named_gpio(fpc1020, "fpc_gpio_irq",
			&fpc1020->irq_gpio);
	if (rc)
	{
		printk("[fp][FPC] fpc1020 request irq fail\n");
		goto exit;
	}

	rc = fpc1020_request_named_gpio(fpc1020, "fpc_gpio_rst",
			&fpc1020->rst_gpio);
	if (rc)
	{
		printk("[fp][FPC] fpc1020 request rst fail\n");
		goto exit;
	}

	//Get 1V8 power Start
	fpc1020->regulator_l22 = regulator_get(dev, "l22");
	if (IS_ERR(fpc1020->regulator_l22))
	{
		printk("[fp][FPC]Fail to get l22 regulator source\n");
		retval = PTR_ERR(fpc1020->regulator_l22);
		return retval;
	}else
	{
		dev_dbg(dev, "Get L22 Regulator Source\n");
	}
	//Get 1V8 power End


	fpc1020->fingerprint_pinctrl = devm_pinctrl_get(dev);
	if (IS_ERR(fpc1020->fingerprint_pinctrl)) {
		if (PTR_ERR(fpc1020->fingerprint_pinctrl) == -EPROBE_DEFER) {
			dev_info(dev, "pinctrl not ready\n");
			rc = -EPROBE_DEFER;
			goto exit;
		}
		dev_err(dev, "Target does not use pinctrl\n");
		fpc1020->fingerprint_pinctrl = NULL;
		rc = -EINVAL;
		goto exit;
	}

	for (i = 0; i < ARRAY_SIZE(fpc1020->pinctrl_state); i++) {
		const char *n = pctl_names[i];
		struct pinctrl_state *state =
			pinctrl_lookup_state(fpc1020->fingerprint_pinctrl, n);
		if (IS_ERR(state)) {
			dev_err(dev, "cannot find '%s'\n", n);
			rc = -EINVAL;
			goto exit;
		}
		dev_info(dev, "found pin control %s\n", n);
		fpc1020->pinctrl_state[i] = state;
	}

	rc = select_pin_ctl(fpc1020, "fpc1020_reset_reset");
	if (rc)
		goto exit;
	rc = select_pin_ctl(fpc1020, "fpc1020_irq_active");
	if (rc)
		goto exit;
	rc = of_property_read_u32(np, "fpc,event-type", &val);
	fpc1020->event_type = rc < 0 ? EV_MSC : val;

	rc = of_property_read_u32(np, "fpc,event-code", &val);
	fpc1020->event_code = rc < 0 ? MSC_SCAN : val;

	fpc1020->idev = devm_input_allocate_device(dev);
	if (!fpc1020->idev) {
		dev_err(dev, "failed to allocate input device\n");
		rc = -ENOMEM;
		goto exit;
	}
	input_set_capability(fpc1020->idev, fpc1020->event_type,
			fpc1020->event_code);
	input_set_capability(fpc1020->idev, fpc1020->event_type,
			MSC_RAW); /* SW15 */
#if 0
	snprintf(fpc1020->idev_name, sizeof(fpc1020->idev_name), "fpc1020@%s",
		dev_name(dev));
#else
        snprintf(fpc1020->idev_name, sizeof(fpc1020->idev_name), "fpc1020");
#endif
	fpc1020->idev->name = fpc1020->idev_name;

	set_bit(EV_KEY,	fpc1020->idev->evbit);
	set_bit(KEY_WAKEUP, fpc1020->idev->keybit);
	rc = input_register_device(fpc1020->idev);
	fpc1020->wakeup_enabled = false; /* SW15 */
	if (rc) {
		dev_err(dev, "failed to register input device\n");
		goto exit;
	}

	irqf = IRQF_TRIGGER_RISING | IRQF_ONESHOT;
	if (of_property_read_bool(dev->of_node, "fpc,enable-wakeup")) {
		irqf |= IRQF_NO_SUSPEND;
		device_init_wakeup(dev, 1);
	}
	mutex_init(&fpc1020->lock);
	rc = devm_request_threaded_irq(dev, gpio_to_irq(fpc1020->irq_gpio),
			NULL, fpc1020_irq_handler, irqf,
			dev_name(dev), fpc1020);
	if (rc) {
		dev_err(dev, "could not request irq %d\n",
				gpio_to_irq(fpc1020->irq_gpio));
		goto exit;
	}
	dev_dbg(dev, "requested irq %d\n", gpio_to_irq(fpc1020->irq_gpio));

	/* Request that the interrupt should be wakeable */
	enable_irq_wake( gpio_to_irq( fpc1020->irq_gpio ) );
	wake_lock_init(&fpc1020->ttw_wl, WAKE_LOCK_SUSPEND, "fpc_ttw_wl"); /* SW15 */
	fpc1020_irq_enable(fpc1020, false);

	rc = sysfs_create_group(&dev->kobj, &attribute_group);
	if (rc) {
		dev_err(dev, "could not create sysfs\n");
		goto exit;
	}

	if (of_property_read_bool(dev->of_node, "fpc,enable-on-boot")) {
		dev_info(dev, "Enabling hardware\n");
		(void)device_prepare(fpc1020, true);
	}

#ifdef CONFIG_FB
	fpc1020->fb_notifier.notifier_call = fb_notifier_callback;
	fb_register_client(&fpc1020->fb_notifier);
#endif
	dev_info(dev, "%s: ok\n", __func__);
	printk("[fp][FPC] fpc1020_probe---\n");
exit:
	return rc;
}

static int fpc1020_remove(struct platform_device *pdev)
{
	struct  fpc1020_data *fpc1020 = dev_get_drvdata(&pdev->dev);

	sysfs_remove_group(&pdev->dev.kobj, &attribute_group);
	mutex_destroy(&fpc1020->lock);
	wake_lock_destroy(&fpc1020->ttw_wl); /* SW15 */
#ifdef CONFIG_FB
	fb_unregister_client(&fpc1020->fb_notifier);
#endif
	dev_info(&pdev->dev, "%s\n", __func__);
	return 0;
}


static struct of_device_id fpc1020_of_match[] = {
	{ .compatible = "fpc,fpc1020", },
	{}
};

#ifdef CONFIG_FB
static int fb_notifier_callback(struct notifier_block *self,
					 unsigned long event, void *data)
{
	struct fb_event *evdata = data;
	int *blank;
	struct fpc1020_data *fpc1020 =
		container_of(self, struct fpc1020_data, fb_notifier);

	printk("%s, event = %ld\n", __func__, event);
	if (evdata && evdata->data && event == FB_EVENT_BLANK) {
		blank = evdata->data;
		switch (*blank) {
		case FB_BLANK_UNBLANK:
			fpc1020->blank = 0;
			break;
		case FB_BLANK_POWERDOWN:
			fpc1020->blank = 1;
			break;
		}
	}

	return 0;
}
#endif
MODULE_DEVICE_TABLE(of, fpc1020_of_match);

#ifdef CONFIG_PM
static int fpc1020_suspend(struct device *dev)
{
    int ret = 0;
    struct fpc1020_data *fpc1020 = dev_get_drvdata(dev);
    int irq_gpio_level;

    pr_info("%s+\n", __func__);

    irq_gpio_level = read_irq_gpio(fpc1020);
    if (irq_gpio_level != 0)
        dev_info(dev, "%s irq_gpio_level:%d\n", __func__, irq_gpio_level);

    pr_info("%s- ret:%d\n", __func__, ret);

    return 0;
}

static int fpc1020_resume(struct device *dev)
{
    int ret = 0;
    struct fpc1020_data *fpc1020 = dev_get_drvdata(dev);
    int irq_gpio_level;

    pr_info("%s+\n", __func__);

    irq_gpio_level = read_irq_gpio(fpc1020);
    if (irq_gpio_level != 0)
        dev_info(dev, "%s irq_gpio_level:%d\n", __func__, irq_gpio_level);

    pr_info("%s- ret:%d\n", __func__, ret);

    return ret;
}

static int fpc1020_suspend_noirq(struct device *dev)
{
    int ret = 0;
    struct fpc1020_data *fpc1020 = dev_get_drvdata(dev);
    int irq_gpio_level;

    pr_info("%s+\n", __func__);

    irq_gpio_level = read_irq_gpio(fpc1020);
    if (irq_gpio_level != 0)
        dev_info(dev, "%s irq_gpio_level:%d\n", __func__, irq_gpio_level);

    pr_info("%s- ret:%d\n", __func__, ret);

    return ret;
}

static int fpc1020_resume_noirq(struct device *dev)
{
    int ret = 0;
    struct fpc1020_data *fpc1020 = dev_get_drvdata(dev);
    int irq_gpio_level;

    pr_info("%s+\n", __func__);

    irq_gpio_level = read_irq_gpio(fpc1020);
    if (irq_gpio_level != 0)
        dev_info(dev, "%s irq_gpio_level:%d\n", __func__, irq_gpio_level);

    pr_info("%s- ret:%d\n", __func__, ret);

    return ret;
}

static const struct dev_pm_ops fpc1020_power_dev_pm_ops = {
    .suspend_noirq = fpc1020_suspend_noirq,
    .resume_noirq = fpc1020_resume_noirq,
    .suspend = fpc1020_suspend,
    .resume = fpc1020_resume,
};
#endif //CONFIG_PM

static struct platform_driver fpc1020_driver = {
	.driver = {
		.name	= "fpc1020",
		.owner	= THIS_MODULE,
		.of_match_table = fpc1020_of_match,
#ifdef CONFIG_PM
		.pm = &fpc1020_power_dev_pm_ops,
#endif
	},
	.probe	= fpc1020_probe,
	.remove	= fpc1020_remove,
};

static void __init fpc1020_init_async(void *unused, async_cookie_t cookie)
{
	platform_driver_register(&fpc1020_driver);
}

static int __init fpc1020_init(void)
{
	printk("%s\n", __func__);
	async_schedule(fpc1020_init_async, NULL);
	return 0;
}

static void __exit fpc1020_exit(void)
{
	printk("%s\n", __func__);
	platform_driver_unregister(&fpc1020_driver);
}

module_init(fpc1020_init);
module_exit(fpc1020_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Aleksej Makarov");
MODULE_AUTHOR("Henrik Tillman <henrik.tillman@fingerprints.com>");
MODULE_DESCRIPTION("FPC1020 Fingerprint sensor device driver.");

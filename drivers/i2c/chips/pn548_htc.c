
#include <linux/of_gpio.h>
#include <linux/platform_device.h>
#include <linux/gpio.h>
#include <linux/i2c.h>
#include <linux/types.h>
#include "pn548_htc.h"


#if NFC_GET_BOOTMODE
#include <linux/htc_flags.h>
#endif 



#define D(x...)	\
	if (is_debug) \
		printk(KERN_DEBUG "[NFC] " x)
#define I(x...) printk(KERN_INFO "[NFC] " x)
#define E(x...) printk(KERN_ERR "[NFC] [Err] " x)


#if NFC_OFF_MODE_CHARGING_LOAD_SWITCH
static unsigned int   pvdd_gpio;
#endif 


int pn548_htc_check_rfskuid(int in_is_alive){
	return in_is_alive;
}


int pn548_htc_get_bootmode(void) {
	char sbootmode[30] = "default";
#if NFC_GET_BOOTMODE
	strlcpy(sbootmode,htc_get_bootmode(),sizeof(sbootmode));
#endif  
	if (strcmp(sbootmode, "offmode_charging") == 0) {
		I("%s: Check bootmode done NFC_BOOT_MODE_OFF_MODE_CHARGING\n",__func__);
		return NFC_BOOT_MODE_OFF_MODE_CHARGING;
	} else if (strcmp(sbootmode, "ftm") == 0) {
		I("%s: Check bootmode done NFC_BOOT_MODE_FTM\n",__func__);
		return NFC_BOOT_MODE_FTM;
	} else if (strcmp(sbootmode, "download") == 0) {
		I("%s: Check bootmode done NFC_BOOT_MODE_DOWNLOAD\n",__func__);
		return NFC_BOOT_MODE_DOWNLOAD;
	} else {
		I("%s: Check bootmode done NFC_BOOT_MODE_NORMAL mode = %s\n",__func__,sbootmode);
		return NFC_BOOT_MODE_NORMAL;
	}
}


void pn548_htc_parse_dt(struct device *dev) {
#if NFC_OFF_MODE_CHARGING_LOAD_SWITCH
	struct device_node *dt = dev->of_node;
	pvdd_gpio = of_get_named_gpio_flags(dt, "nxp,pvdd-gpio",0, NULL);
	I("%s: pvdd_gpio:%d\n", __func__, pvdd_gpio);
#endif
}

void pn548_htc_off_mode_charging (void) {
#if NFC_OFF_MODE_CHARGING_LOAD_SWITCH
	I("%s: Turn off NFC_PVDD \n", __func__);
	gpio_set_value(pvdd_gpio, 0);
#endif
}

#include <linux/platform_device.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/of_gpio.h>
#include <linux/i2c.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <asm/debug_display.h>
#include "../../../drivers/video/msm/mdss/mdss_dsi.h"

struct dsi_power_data {
	uint32_t sysrev;         
	struct regulator *vci; 	 
	int vdd1v8;
};

static int htc_hiaaero_regulator_init(struct platform_device *pdev)
{
	int ret = 0;
	struct mdss_dsi_ctrl_pdata *ctrl_pdata = NULL;
	struct dsi_power_data *pwrdata = NULL;

	PR_DISP_INFO("%s\n", __func__);
	if (!pdev) {
		PR_DISP_ERR("%s: invalid input\n", __func__);
		return -EINVAL;
	}

	ctrl_pdata = platform_get_drvdata(pdev);
	if (!ctrl_pdata) {
		PR_DISP_ERR("%s: invalid driver data\n", __func__);
		return -EINVAL;
	}

	pwrdata = devm_kzalloc(&pdev->dev,
				sizeof(struct dsi_power_data), GFP_KERNEL);
	if (!pwrdata) {
		PR_DISP_ERR("%s: FAILED to alloc pwrdata\n", __func__);
		return -ENOMEM;
	}

	ctrl_pdata->dsi_pwrctrl_data = pwrdata;

	pwrdata->vci = devm_regulator_get(&pdev->dev, "vdd");
	if (IS_ERR(pwrdata->vci)) {
		PR_DISP_ERR("%s: could not get vdda vreg, rc=%ld\n",
			__func__, PTR_ERR(pwrdata->vci));
		return PTR_ERR(pwrdata->vci);
	}

	
	ret = regulator_set_voltage(pwrdata->vci, 3000000, 3000000);
	if (ret) {
		PR_DISP_ERR("%s: set voltage failed on vdda vreg, rc=%d\n",
			__func__, ret);
		return ret;
	}

	pwrdata->vdd1v8 = of_get_named_gpio(pdev->dev.of_node,
						"htc,vdd1v8-gpio", 0);
	
	return 0;
}

static int htc_hiaaero_regulator_deinit(struct platform_device *pdev)
{
	
	return 0;
}

void htc_hiaaero_panel_reset(struct mdss_panel_data *pdata, int enable)
{
	struct mdss_dsi_ctrl_pdata *ctrl_pdata = NULL;
	struct dsi_power_data *pwrdata = NULL;

	if (pdata == NULL) {
		PR_DISP_ERR("%s: Invalid input data\n", __func__);
		return;
	}
	ctrl_pdata = container_of(pdata, struct mdss_dsi_ctrl_pdata, panel_data);
	pwrdata = ctrl_pdata->dsi_pwrctrl_data;

	if (!gpio_is_valid(ctrl_pdata->rst_gpio)) {
		PR_DISP_DEBUG("%s:%d, reset line not configured\n",
			   __func__, __LINE__);
		return;
	}

	PR_DISP_INFO("%s: enable = %d\n", __func__, enable);

	if (enable) {
		if (pdata->panel_info.first_power_on == 1) {
			PR_DISP_INFO("reset already on in first time\n");
			return;
		}
		gpio_set_value(ctrl_pdata->rst_gpio, 1);
		usleep_range(2000, 2500);
		gpio_set_value(ctrl_pdata->rst_gpio, 0);
		usleep_range(1000, 1500);
		gpio_set_value(ctrl_pdata->rst_gpio, 1);
		usleep_range(10000, 10500);

	} else {
		gpio_set_value(ctrl_pdata->rst_gpio, 0);
		usleep_range(10000,10500);
	}

	PR_DISP_INFO("%s: enable = %d done\n", __func__, enable);
}

static int htc_hiaaero_panel_power_on(struct mdss_panel_data *pdata, int enable)
{
	int ret;

	struct mdss_dsi_ctrl_pdata *ctrl_pdata = NULL;
	struct dsi_power_data *pwrdata = NULL;

	PR_DISP_INFO("%s: en=%d\n", __func__, enable);
	if (pdata == NULL) {
		PR_DISP_ERR("%s: Invalid input data\n", __func__);
		return -EINVAL;
	}

	ctrl_pdata = container_of(pdata, struct mdss_dsi_ctrl_pdata, panel_data);
	pwrdata = ctrl_pdata->dsi_pwrctrl_data;

	if (!pwrdata) {
		PR_DISP_ERR("%s: pwrdata not initialized\n", __func__);
		return -EINVAL;
	}

	if (enable) {
		
		ret = regulator_set_optimum_mode(pwrdata->vci, 100000);
		if (ret < 0) {
			PR_DISP_ERR("%s: vdda set opt mode failed.\n",
				__func__);
			return ret;
		}
		ret = regulator_enable(pwrdata->vci);
		if (ret) {
			PR_DISP_ERR("%s: Failed to enable regulator.\n",__func__);
			return ret;
		}
		usleep_range(1000,1500);
		
		gpio_set_value(pwrdata->vdd1v8, 1);
	} else {
		
		gpio_set_value(pwrdata->vdd1v8, 0);
		
		
		ret = regulator_disable(pwrdata->vci);
		if (ret) {
			PR_DISP_ERR("%s: Failed to disable vdda regulator.\n",
				__func__);
			return ret;
		}
		ret = regulator_set_optimum_mode(pwrdata->vci, 100);
		if (ret < 0) {
			PR_DISP_ERR("%s: vddpll_vreg set opt mode failed.\n",
				__func__);
			return ret;
		}
	}
	PR_DISP_INFO("%s: en=%d done\n", __func__, enable);

	return 0;
}

static struct mdss_dsi_pwrctrl dsi_pwrctrl = {
	.dsi_regulator_init = htc_hiaaero_regulator_init,
	.dsi_regulator_deinit = htc_hiaaero_regulator_deinit,
	.dsi_power_on = htc_hiaaero_panel_power_on,
	.dsi_panel_reset = htc_hiaaero_panel_reset,

};

static struct platform_device dsi_pwrctrl_device = {
	.name          = "mdss_dsi_pwrctrl",
	.id            = -1,
	.dev.platform_data = &dsi_pwrctrl,
};

int __init htc_8952_dsi_panel_power_register(void)
{
       int ret;

       ret = platform_device_register(&dsi_pwrctrl_device);
       if (ret) {
               pr_err("[DISP] %s: dsi_pwrctrl_device register failed! ret =%x\n",__func__, ret);
               return ret;
       }
       return 0;
}
arch_initcall(htc_8952_dsi_panel_power_register);

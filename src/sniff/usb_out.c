#include "usb_out.h"

#include <zephyr/device.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/ring_buffer.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(sniffer_usb, LOG_LEVEL_INF);

#define DATA_UART_NODE DT_NODELABEL(cdc_acm_data)
BUILD_ASSERT(DT_NODE_HAS_STATUS(DATA_UART_NODE, okay),
	     "cdc_acm_data node missing - is boards/nrf52840dongle_nrf52840.overlay applied?");

#define TX_RING_BYTES 16384

#define TX_WATERMARK_BYTES  512U
#define TX_FLUSH_PERIOD_MS  2

static uint8_t tx_ring_storage[TX_RING_BYTES];
static struct ring_buf tx_ring;

static const struct device *data_dev;
static atomic_t dropped_records;
static atomic_t bytes_written_lo;
static atomic_t bytes_written_hi;
static atomic_t dtr_set;

static struct k_spinlock lock;

static void tx_flush_timer_handler(struct k_timer *t);
static K_TIMER_DEFINE(tx_flush_timer, tx_flush_timer_handler, NULL);

static void bytes_written_add(size_t n)
{
	uint32_t before = (uint32_t)atomic_add(&bytes_written_lo, n);
	uint32_t after = before + (uint32_t)n;
	if (after < before) {
		atomic_inc(&bytes_written_hi);
	}
}

static void tx_irq_handler(const struct device *dev, void *user_data)
{
	ARG_UNUSED(user_data);

	while (uart_irq_update(dev) && uart_irq_is_pending(dev)) {
		if (uart_irq_tx_ready(dev)) {
			uint8_t *data;
			uint32_t claimed;
			int wrote = 0;

			K_SPINLOCK(&lock) {
				claimed = ring_buf_get_claim(&tx_ring, &data,
							      sizeof(tx_ring_storage));
			}

			if (claimed == 0U) {
				uart_irq_tx_disable(dev);
				break;
			}

			wrote = uart_fifo_fill(dev, data, claimed);
			if (wrote > 0) {
				bytes_written_add((size_t)wrote);
			}

			K_SPINLOCK(&lock) {
				(void)ring_buf_get_finish(&tx_ring,
							   (wrote > 0) ? (uint32_t)wrote : 0U);
			}
		}

		if (uart_irq_rx_ready(dev)) {
			uint8_t scratch[32];
			(void)uart_fifo_read(dev, scratch, sizeof(scratch));
		}
	}
}

static void tx_flush_timer_handler(struct k_timer *t)
{
	ARG_UNUSED(t);

	if (data_dev == NULL) {
		return;
	}
	if (ring_buf_size_get(&tx_ring) > 0U) {
		uart_irq_tx_enable(data_dev);
	}
}

int sniffer_usb_out_init(void)
{
	data_dev = DEVICE_DT_GET(DATA_UART_NODE);
	if (!device_is_ready(data_dev)) {
		LOG_ERR("cdc_acm_data device not ready");
		return -ENODEV;
	}

	ring_buf_init(&tx_ring, sizeof(tx_ring_storage), tx_ring_storage);

	uart_irq_rx_disable(data_dev);
	uart_irq_tx_disable(data_dev);
	uart_irq_callback_user_data_set(data_dev, tx_irq_handler, NULL);
	uart_irq_rx_enable(data_dev);

	k_timer_start(&tx_flush_timer,
		      K_MSEC(TX_FLUSH_PERIOD_MS),
		      K_MSEC(TX_FLUSH_PERIOD_MS));
	return 0;
}

int sniffer_usb_out_write(const uint8_t *data, size_t len)
{
	if (data == NULL || len == 0U) {
		return 0;
	}
	if (data_dev == NULL) {
		return -ENODEV;
	}

	bool dropped = false;
	size_t queued = 0U;

	K_SPINLOCK(&lock) {
		if (ring_buf_space_get(&tx_ring) < len) {
			dropped = true;
			K_SPINLOCK_BREAK;
		}
		(void)ring_buf_put(&tx_ring, data, len);
		queued = ring_buf_size_get(&tx_ring);
	}

	if (dropped) {
		atomic_inc(&dropped_records);
		return -ENOMEM;
	}

	if (queued >= TX_WATERMARK_BYTES) {
		uart_irq_tx_enable(data_dev);
	}
	return 0;
}

uint32_t sniffer_usb_out_dropped_records(void)
{
	return (uint32_t)atomic_get(&dropped_records);
}

uint64_t sniffer_usb_out_bytes_written(void)
{
	uint32_t lo = (uint32_t)atomic_get(&bytes_written_lo);
	uint32_t hi = (uint32_t)atomic_get(&bytes_written_hi);
	return ((uint64_t)hi << 32) | lo;
}

bool sniffer_usb_out_dtr(void)
{
	uint32_t dtr = 0U;

	if (data_dev == NULL) {
		return false;
	}
	if (uart_line_ctrl_get(data_dev, UART_LINE_CTRL_DTR, &dtr) != 0) {
		return (bool)atomic_get(&dtr_set);
	}
	atomic_set(&dtr_set, (atomic_val_t)dtr);
	return dtr != 0U;
}

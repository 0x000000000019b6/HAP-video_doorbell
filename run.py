import signal
from hap_video_doorbell import (
    Logger, AccessoryDriver, hap_protocol,
    VideoDoorbell, Camera
)

# hap_protocol.logger = Logger.getLogger('hap_protocol')

driver = AccessoryDriver(
    port = 51826, 
    persist_file = 'accessory.state'
    )

accessory = VideoDoorbell(
    driver = driver,
    display_name = 'VideoDoorbell',
    doorbell_button_gpio_pin = 11,
    gpio_board = 'BOARD',
    trigger_doorbell = False
    )

driver.add_accessory(accessory)

signal.signal(signal.SIGTERM, driver.signal_handler)

driver.start()


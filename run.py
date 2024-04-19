import signal
from hap_video_doorbell import (
    Logger, AccessoryDriver, hap_protocol,
    VideoDoorbell, Camera
)

logger = Logger.getLogger(__name__)

hap_protocol_logger = Logger.getLogger('hap_protocol')

# hap_protocol.logger = hap_protocol_logger

driver = AccessoryDriver(port=51826, persist_file='accessory.state')

# acc = Camera(
#     CAMERA_OPTIONS,
#     driver,
#     'Camera'
#     )

acc = VideoDoorbell(
    driver = driver,
    display_name = 'VideoDoorbell',
    doorbell_button_gpio_pin = 11,
    gpio_board = 'BOARD'
    )

driver.add_accessory(accessory=acc)

signal.signal(signal.SIGTERM, driver.signal_handler)

driver.start()


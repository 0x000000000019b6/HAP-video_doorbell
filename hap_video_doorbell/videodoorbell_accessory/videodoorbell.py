from pyhap.accessory_driver import AccessoryDriver, Accessory
from pyhap.iid_manager import IIDManager
from pyhap.const import CATEGORY_VIDEO_DOOR_BELL
from ..camera_accessory import Camera
from ..utils.logger import Logger
import typing as t

if t.TYPE_CHECKING:
     import RPi.GPIO as GPIO

class VideoDoorbell(Camera):

     category = CATEGORY_VIDEO_DOOR_BELL

     log = Logger.getLogger('VideoDoorbell')

#     def __init__(self,
#                 driver: "AccessoryDriver",
#                 display_name: str = "VideoDoorbell",
#                 firmware_revision: str = "1.0.0",
#                 manufacturer: str = "PyHAP",
#                 model: str = "VideoDoorbell",
#                 serial_number: str = None,
#                 dev_video: str = '/dev/video0',
#                 dev_audio: str | None = 'hw:1,0',
#                 push_button_gpio_pin: int | None = 17, # WM8960-Audio-HAT gpio board button
#                 ffmpeg_debug: bool = True,
#                 max_stream_count: int = 5,
#                 overwrite_device_address: str = None,
#                 date_caption: str = '%Y-%m-%d %H-%M-%S',
#                 **kwargs
#                 ):
    
     def __init__(self, 
               driver: AccessoryDriver,
               display_name: str,
               aid: int = None,
               iid_manager: IIDManager = None,
               ffmpeg_debug: bool = True,
               logger: Logger = None,

               doorbell_button_gpio_pin: int | None = None, # WM8960-Audio-HAT button gpio BCM: 17, BOARD: 11
               gpio_board: t.Literal['BOARD', 'BCM'] = 'BCM',
               trigger_doorbell: bool = True,

               ):
          
          self.__doorbell_button_gpio_pin = doorbell_button_gpio_pin
          self.__trigger_doorbell = trigger_doorbell
          self.__gpio_board: str = gpio_board
          self.__gpio: 'GPIO' = None
        
          super().__init__(
               driver = driver,
               display_name = display_name,
               aid = aid,
               iid_manager = iid_manager,
               ffmpeg_debug = ffmpeg_debug,
               logger = logger,

          )


          self.doorbell_service = self.add_preload_service("Doorbell")

          self.doorbell_switch = self.doorbell_service.configure_char(
               "ProgrammableSwitchEvent",
               value=0,
               valid_values={"SinglePress": 0},
               # getter_callback = self._get_doorbell_state
          )

          self.set_primary_service(self.doorbell_service)

          if self.__doorbell_button_gpio_pin is not None:
               self.__setup_doorbell_button_gpio()

     def __setup_doorbell_button_gpio(self):

          import RPi.GPIO as GPIO

          self.__gpio = GPIO

          self.log.debug("GPIO version: %s" % (str(GPIO.VERSION)))

          GPIO.setwarnings(False)

          GPIO.setmode(getattr(GPIO, self.__gpio_board))
          GPIO.setup(self.__doorbell_button_gpio_pin, GPIO.IN, pull_up_down = GPIO.PUD_DOWN)

          GPIO.add_event_detect(self.__doorbell_button_gpio_pin, GPIO.RISING, callback=self.__doorbell_button_callback)
     
     def __doorbell_button_callback(self, gpio_pin: int):

          if gpio_pin == self.__doorbell_button_gpio_pin:

               self.log.info("Doorbell button pressed -> %s: %s" % (
                    str(self.__gpio_board),
                    str(gpio_pin)
                    ))
               
               if self.__trigger_doorbell == True:
               
                    self.doorbell_switch.set_value(0)

     async def stop(self):

          if self.__gpio is not None:
               self.log.debug("GPIO cleanup!")
               self.__gpio.cleanup()

          return await super().stop()
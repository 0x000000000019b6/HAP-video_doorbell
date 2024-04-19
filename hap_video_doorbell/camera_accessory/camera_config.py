from pyhap import util as pyhap_util
from dataclasses import dataclass, asdict
import ipaddress

@dataclass
class CameraConfig:
    display_name: str
    dev_video: str
    ffmpeg_path: str
    ffmpeg_debug: bool
    stream_count: int
    date_caption: str
    stream_address: str = None
    stream_address_isv6: bytes = None
    srtp: bool = True
    
    # start_stream_cmd: str = None

    def __post_init__(self):
        self.stream_address = pyhap_util.get_local_address() if self.stream_address is None else self.stream_address     
    
        try:
            ipaddress.IPv4Address(self.stream_address)
            self.stream_address_isv6 = b'\x00'
        except ValueError:
            self.stream_address_isv6 = b'\x01'

    @property
    def start_stream_cmd(self):

        cmd = ""

        cmd += (
            self.ffmpeg_path + ' -re '
            '-f video4linux2 -i ' + self.dev_video + " "
             
            '-an '
            '-threads 4 '
            '-vcodec libx264 '
            '-pix_fmt yuv420p -color_range mpeg -r {fps} -f rawvideo -preset ultrafast -tune zerolatency '
            '-vf scale={width}:{height} -b:v {v_max_bitrate}k -bufsize {v_max_bitrate}k '
            '-payload_type 99 -ssrc {v_ssrc} -f rtp '
            '-srtp_out_suite AES_CM_128_HMAC_SHA1_80 -srtp_out_params {v_srtp_key} '
            'srtp://{address}:{v_port}?rtcpport={v_port}&'
            'localrtcpport={v_port}&pkt_size=1316 '
        )

        cmd = cmd.replace("  ", " ")

        print(cmd)

        return cmd

    @property
    def dict(self):
        return {k: v for k, v in asdict(self).items()}
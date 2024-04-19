from pyhap.accessory import Accessory, Bridge
from pyhap.accessory_driver import AccessoryDriver
from pyhap.const import CATEGORY_CAMERA, HAP_REPR_VALUE
from pyhap import util as pyhap_camera_util
from .camera_config import CameraConfig

import asyncio
import functools
import ipaddress
import os
import struct
from uuid import UUID
import subprocess
import io
from PIL import Image
import async_timeout
import logging
import socket

from pyhap import RESOURCE_DIR, tlv
from pyhap.accessory import Accessory
from pyhap.const import CATEGORY_CAMERA
from pyhap.util import byte_bool, to_base64_str
from pyhap.camera import (
    SRTP_CRYPTO_SUITES, 
)
from pyhap import camera
from .options import CAMERA_OPTIONS
from pyhap.iid_manager import IIDManager
from ..utils.logger import Logger
from .snapshot import Snapshot
from time import sleep
from .port_picker import FreePortPicker
from .ffmpeg_process import FfmpegProcess
import aiofiles

class Camera(Accessory):
    """An Accessory that can negotiated camera stream settings with iOS and start a
    stream.
    """

    category = CATEGORY_CAMERA

    log = Logger.getLogger('Camera')

    def __init__(self, 
               driver: AccessoryDriver,
               display_name: str,
               aid: int = None,
               iid_manager: IIDManager = None,
               ):

        options = CAMERA_OPTIONS

        self.has_srtp = options.get('srtp', False)
        self.start_stream_cmd = options.get('start_stream_cmd', camera.FFMPEG_CMD)
        self.start_audio_return_stream_cmd = options.get('start_audio_return_stream_cmd', None)
        self.audio_return_stream_sdp = options.get('audio_return_stream_sdp', None)

        self.stream_address = options['address']
        try:
            ipaddress.IPv4Address(self.stream_address)
            self.stream_address_isv6 = b'\x00'
        except ValueError:
            self.stream_address_isv6 = b'\x01'
        self.sessions = {}

        self.async_get_snapshot = Snapshot(
            ffmpeg_path = "/bin/ffmpeg",
            dev_video = "/dev/video0",
            log = self.log.getChild('Snapshot'),
            cache_timeout = 5
        )

        super().__init__(
            driver = driver,
            display_name = display_name,
            aid = aid,
            iid_manager = iid_manager
        )

        self.microphone = self.add_preload_service('Microphone')

        self.microphone.configure_char(
            "Mute", value=1
        )

        # self.microphone.configure_char(
        #     "Volume", value=100, setter_callback = self.__set_microphone_volume,
        # )

        self.speaker = self.add_preload_service('Speaker')

        self.speaker.configure_char(
            "Mute", value=1
        )

        # self.speaker.configure_char(
        #     "Volume", value=100, setter_callback = self.__set_speaker_volume,
        # )

        self._streaming_status = []
        self._management = []
        self._setup_stream_management(options)
    

    @Accessory.run_at_interval(1)
    async def run(self):

        pass

    @property
    def streaming_status(self):
        """For backwards compatibility."""
        return self._streaming_status[0]

    def _setup_stream_management(self, options):
        """Create stream management."""
        stream_count = options.get("stream_count", 1)
        for stream_idx in range(stream_count):
            self._management.append(self._create_stream_management(stream_idx, options))
            self._streaming_status.append(camera.STREAMING_STATUS["AVAILABLE"])

    def _create_stream_management(self, stream_idx, options):
        """Create a stream management service."""
        management = self.add_preload_service("CameraRTPStreamManagement", unique_id=stream_idx)
        management.configure_char(
            "StreamingStatus",
            getter_callback=lambda: self._get_streaming_status(stream_idx),
        )
        management.configure_char(
            "SupportedRTPConfiguration",
            value=self.get_supported_rtp_config(options.get("srtp", False)),
        )
        management.configure_char(
            "SupportedVideoStreamConfiguration",
            value=self.get_supported_video_stream_config(options["video"]),
        )
        management.configure_char(
            "SupportedAudioStreamConfiguration",
            value=self.get_supported_audio_stream_config(options["audio"]),
        )
        management.configure_char(
            "SelectedRTPStreamConfiguration",
            setter_callback=self.set_selected_stream_configuration,
        )
        management.configure_char(
            "SetupEndpoints",
            setter_callback=lambda value: self.set_endpoints(
                value, stream_idx=stream_idx
            ),
        )
        return management

    async def _start_stream(self, objs, reconfigure):  # pylint: disable=unused-argument
        """Start or reconfigure video streaming for the given session.

        Schedules ``self.start_stream`` or ``self.reconfigure``.

        No support for reconfigure currently.

        :param objs: TLV-decoded SelectedRTPStreamConfiguration
        :type objs: ``dict``

        :param reconfigure: Whether the stream should be reconfigured instead of
            started.
        :type reconfigure: bool
        """
        video_tlv = objs.get(camera.SELECTED_STREAM_CONFIGURATION_TYPES['VIDEO'])
        audio_tlv = objs.get(camera.SELECTED_STREAM_CONFIGURATION_TYPES['AUDIO'])

        opts = {}

        if video_tlv:
            video_objs = tlv.decode(video_tlv)

            video_codec_params = video_objs.get(camera.VIDEO_TYPES['CODEC_PARAM'])
            if video_codec_params:
                video_codec_param_objs = tlv.decode(video_codec_params)
                opts['v_profile_id'] = \
                    video_codec_param_objs[camera.VIDEO_CODEC_PARAM_TYPES['PROFILE_ID']]
                opts['v_level'] = \
                    video_codec_param_objs[camera.VIDEO_CODEC_PARAM_TYPES['LEVEL']]

            video_attrs = video_objs.get(camera.VIDEO_TYPES['ATTRIBUTES'])
            if video_attrs:
                video_attr_objs = tlv.decode(video_attrs)
                opts['width'] = struct.unpack('<H',
                            video_attr_objs[camera.VIDEO_ATTRIBUTES_TYPES['IMAGE_WIDTH']])[0]
                opts['height'] = struct.unpack('<H',
                            video_attr_objs[camera.VIDEO_ATTRIBUTES_TYPES['IMAGE_HEIGHT']])[0]
                opts['fps'] = struct.unpack('<B',
                                video_attr_objs[camera.VIDEO_ATTRIBUTES_TYPES['FRAME_RATE']])[0]

            video_rtp_param = video_objs.get(camera.VIDEO_TYPES['RTP_PARAM'])
            if video_rtp_param:
                video_rtp_param_objs = tlv.decode(video_rtp_param)
                if camera.RTP_PARAM_TYPES['SYNCHRONIZATION_SOURCE'] in video_rtp_param_objs:
                    opts['v_ssrc'] = struct.unpack('<I',
                        video_rtp_param_objs.get(
                            camera.RTP_PARAM_TYPES['SYNCHRONIZATION_SOURCE']))[0]
                if camera.RTP_PARAM_TYPES['PAYLOAD_TYPE'] in video_rtp_param_objs:
                    opts['v_payload_type'] = \
                        video_rtp_param_objs.get(camera.RTP_PARAM_TYPES['PAYLOAD_TYPE'])
                if camera.RTP_PARAM_TYPES['MAX_BIT_RATE'] in video_rtp_param_objs:
                    opts['v_max_bitrate'] = struct.unpack('<H',
                        video_rtp_param_objs.get(camera.RTP_PARAM_TYPES['MAX_BIT_RATE']))[0]
                if camera.RTP_PARAM_TYPES['RTCP_SEND_INTERVAL'] in video_rtp_param_objs:
                    opts['v_rtcp_interval'] = struct.unpack('<f',
                        video_rtp_param_objs.get(camera.RTP_PARAM_TYPES['RTCP_SEND_INTERVAL']))[0]
                if camera.RTP_PARAM_TYPES['MAX_MTU'] in video_rtp_param_objs:
                    opts['v_max_mtu'] = video_rtp_param_objs.get(camera.RTP_PARAM_TYPES['MAX_MTU'])

        if audio_tlv:
            audio_objs = tlv.decode(audio_tlv)

            opts['a_codec'] = audio_objs[camera.AUDIO_TYPES['CODEC']]
            audio_codec_param_objs = tlv.decode(
                                        audio_objs[camera.AUDIO_TYPES['CODEC_PARAM']])
            audio_rtp_param_objs = tlv.decode(
                                        audio_objs[camera.AUDIO_TYPES['RTP_PARAM']])
            opts['a_comfort_noise'] = audio_objs[camera.AUDIO_TYPES['COMFORT_NOISE']]

            opts['a_channel'] = \
                audio_codec_param_objs[camera.AUDIO_CODEC_PARAM_TYPES['CHANNEL']][0]
            opts['a_bitrate'] = struct.unpack('?',
                audio_codec_param_objs[camera.AUDIO_CODEC_PARAM_TYPES['BIT_RATE']])[0]
            opts['a_sample_rate'] = 8 * (
                1 + audio_codec_param_objs[camera.AUDIO_CODEC_PARAM_TYPES['SAMPLE_RATE']][0])
            opts['a_packet_time'] = struct.unpack('<B',
                audio_codec_param_objs[camera.AUDIO_CODEC_PARAM_TYPES['PACKET_TIME']])[0]

            opts['a_ssrc'] = struct.unpack('<I',
                audio_rtp_param_objs[camera.RTP_PARAM_TYPES['SYNCHRONIZATION_SOURCE']])[0]
            opts['a_payload_type'] = audio_rtp_param_objs[camera.RTP_PARAM_TYPES['PAYLOAD_TYPE']]
            opts['a_max_bitrate'] = struct.unpack('<H',
                audio_rtp_param_objs[camera.RTP_PARAM_TYPES['MAX_BIT_RATE']])[0]
            opts['a_rtcp_interval'] = struct.unpack('<f',
                audio_rtp_param_objs[camera.RTP_PARAM_TYPES['RTCP_SEND_INTERVAL']])[0]
            opts['a_comfort_payload_type'] = \
                audio_rtp_param_objs[camera.RTP_PARAM_TYPES['COMFORT_NOISE_PAYLOAD_TYPE']]

        session_objs = tlv.decode(objs[camera.SELECTED_STREAM_CONFIGURATION_TYPES['SESSION']])
        session_id = UUID(bytes=session_objs[camera.SETUP_TYPES['SESSION_ID']])
        session_info = self.sessions[session_id]
        stream_idx = session_info['stream_idx']

        opts.update(session_info)
        success = await self.reconfigure_stream(session_info, opts) if reconfigure \
            else await self.start_stream(session_info, opts)

        if success:
            self._streaming_status[stream_idx] = camera.STREAMING_STATUS['STREAMING']
        else:
            self.log.error(
                '[%s] Failed to start/reconfigure stream, deleting session.',
                session_id
            )
            del self.sessions[session_id]
            self._streaming_status[stream_idx] = camera.STREAMING_STATUS['AVAILABLE']

    def _get_streaming_status(self, stream_idx):
        """Get the streaming status in TLV format.

        Called when iOS reads the StreaminStatus ``Characteristic``.
        """
        return tlv.encode(b'\x01', self._streaming_status[stream_idx], to_base64=True)

    async def _stop_stream(self, objs):
        """Stop the stream for the specified session.

        Schedules ``self.stop_stream``.

        :param objs: TLV-decoded SelectedRTPStreamConfiguration value.
        :param objs: ``dict``
        """
        session_objs = tlv.decode(objs[camera.SELECTED_STREAM_CONFIGURATION_TYPES['SESSION']])
        session_id = UUID(bytes=session_objs[camera.SETUP_TYPES['SESSION_ID']])

        session_info = self.sessions.get(session_id)
        if not session_info:
            self.log.error(
                'Requested to stop stream for session %s, but no '
                'such session was found',
                session_id
            )
            return

        stream_idx = session_info['stream_idx']
        await self.stop_stream(session_info)
        await self.stop_audio_return_stream(session_info)
        del self.sessions[session_id]

        self._streaming_status[stream_idx] = camera.STREAMING_STATUS['AVAILABLE']

    def set_selected_stream_configuration(self, value):
        """Set the selected stream configuration.

        Called from iOS to set the SelectedRTPStreamConfiguration ``Characteristic``.

        This method schedules a stream for the session in ``value`` to be start, stopped
        or reconfigured, depending on the request.

        :param value: base64-encoded selected configuration in TLV format
        :type value: ``str``
        """
        self.log.debug('set_selected_stream_config - value - %s', value)

        objs = tlv.decode(value, from_base64=True)
        if camera.SELECTED_STREAM_CONFIGURATION_TYPES['SESSION'] not in objs:
            self.log.error('Bad request to set selected stream configuration.')
            return

        session = tlv.decode(objs[camera.SELECTED_STREAM_CONFIGURATION_TYPES['SESSION']])

        request_type = session[b'\x02'][0]
        self.log.debug('Set stream config request: %d', request_type)
        if request_type == 1:
            job = functools.partial(self._start_stream, reconfigure=False)
        elif request_type == 0:
            job = self._stop_stream
        elif request_type == 4:
            job = functools.partial(self._start_stream, reconfigure=True)
        else:
            self.log.error('Unknown request type %d', request_type)
            return

        self.driver.add_job(job, objs)

    def set_streaming_available(self, stream_idx):
        """Send an update to the controller that streaming is available."""
        self._streaming_status[stream_idx] = camera.STREAMING_STATUS["AVAILABLE"]
        self._management[stream_idx].get_characteristic("StreamingStatus").notify()


    
        
    def set_endpoints(self, value, stream_idx=None):
        """Configure streaming endpoints.

        Called when iOS sets the SetupEndpoints ``Characteristic``. The endpoint
        information for the camera should be set as the current value of SetupEndpoints.

        :param value: The base64-encoded stream session details in TLV format.
        :param value: ``str``
        """
        if stream_idx is None:
            stream_idx = 0

        objs = tlv.decode(value, from_base64=True)
        session_id = UUID(bytes=objs[camera.SETUP_TYPES['SESSION_ID']])

        # Extract address info
        address_tlv = objs[camera.SETUP_TYPES['ADDRESS']]
        address_info_objs = tlv.decode(address_tlv)
        is_ipv6 = struct.unpack('?',
            address_info_objs[camera.SETUP_ADDR_INFO['ADDRESS_VER']])[0]
        address = address_info_objs[camera.SETUP_ADDR_INFO['ADDRESS']].decode('utf8')
        target_video_port = struct.unpack(
            '<H', address_info_objs[camera.SETUP_ADDR_INFO['VIDEO_RTP_PORT']])[0]
        target_audio_port = struct.unpack(
            '<H', address_info_objs[camera.SETUP_ADDR_INFO['AUDIO_RTP_PORT']])[0]
        
        port_picker = FreePortPicker(
            ipv6 = is_ipv6
        )

        video_return_port = port_picker.get()
        audio_return_port = port_picker.get()

        # Video SRTP Params
        video_srtp_tlv = objs[camera.SETUP_TYPES['VIDEO_SRTP_PARAM']]
        video_info_objs = tlv.decode(video_srtp_tlv)
        video_crypto_suite = video_info_objs[camera.SETUP_SRTP_PARAM['CRYPTO']][0]
        video_master_key = video_info_objs[camera.SETUP_SRTP_PARAM['MASTER_KEY']]
        video_master_salt = video_info_objs[camera.SETUP_SRTP_PARAM['MASTER_SALT']]

        # Audio SRTP Params
        audio_srtp_tlv = objs[camera.SETUP_TYPES['AUDIO_SRTP_PARAM']]
        audio_info_objs = tlv.decode(audio_srtp_tlv)
        audio_crypto_suite = audio_info_objs[camera.SETUP_SRTP_PARAM['CRYPTO']][0]
        audio_master_key = audio_info_objs[camera.SETUP_SRTP_PARAM['MASTER_KEY']]
        audio_master_salt = audio_info_objs[camera.SETUP_SRTP_PARAM['MASTER_SALT']]

        self.log.debug(
            'Received endpoint configuration:'
            '\nsession_id: %s\naddress: %s\nis_ipv6: %s'
            '\ntarget_video_port: %s\ntarget_audio_port: %s'
            '\nvideo_return_port: %s\naudio_return_port: %s'
            '\nvideo_crypto_suite: %s\nvideo_srtp: %s'
            '\naudio_crypto_suite: %s\naudio_srtp: %s',
            session_id, address, is_ipv6, target_video_port, target_audio_port, video_return_port, audio_return_port,
            video_crypto_suite,
            to_base64_str(video_master_key + video_master_salt),
            audio_crypto_suite,
            to_base64_str(audio_master_key + audio_master_salt)
        )

        # Configure the SetupEndpoints response

        if self.has_srtp:
            video_srtp_tlv = tlv.encode(
                camera.SETUP_SRTP_PARAM['CRYPTO'], SRTP_CRYPTO_SUITES['AES_CM_128_HMAC_SHA1_80'],
                camera.SETUP_SRTP_PARAM['MASTER_KEY'], video_master_key,
                camera.SETUP_SRTP_PARAM['MASTER_SALT'], video_master_salt)

            audio_srtp_tlv = tlv.encode(
                camera.SETUP_SRTP_PARAM['CRYPTO'], SRTP_CRYPTO_SUITES['AES_CM_128_HMAC_SHA1_80'],
                camera.SETUP_SRTP_PARAM['MASTER_KEY'], audio_master_key,
                camera.SETUP_SRTP_PARAM['MASTER_SALT'], audio_master_salt)
        else:
            video_srtp_tlv = camera.NO_SRTP
            audio_srtp_tlv = camera.NO_SRTP

        video_ssrc = int.from_bytes(os.urandom(3), byteorder="big")
        audio_ssrc = int.from_bytes(os.urandom(3), byteorder="big")

        res_address_tlv = tlv.encode(
            camera.SETUP_ADDR_INFO['ADDRESS_VER'], self.stream_address_isv6,
            camera.SETUP_ADDR_INFO['ADDRESS'], self.stream_address.encode('utf-8'),
            # camera.SETUP_ADDR_INFO['VIDEO_RTP_PORT'], struct.pack('<H', target_video_port),
            # camera.SETUP_ADDR_INFO['AUDIO_RTP_PORT'], struct.pack('<H', target_audio_port)
            camera.SETUP_ADDR_INFO['VIDEO_RTP_PORT'], struct.pack('<H', video_return_port),
            camera.SETUP_ADDR_INFO['AUDIO_RTP_PORT'], struct.pack('<H', audio_return_port)
            )
        
        # print("res_address_tlv: %s" % (str(res_address_tlv)))

        response_tlv = tlv.encode(
            camera.SETUP_TYPES['SESSION_ID'], session_id.bytes,
            camera.SETUP_TYPES['STATUS'], camera.SETUP_STATUS['SUCCESS'],
            camera.SETUP_TYPES['ADDRESS'], res_address_tlv,
            camera.SETUP_TYPES['VIDEO_SRTP_PARAM'], video_srtp_tlv,
            camera.SETUP_TYPES['AUDIO_SRTP_PARAM'], audio_srtp_tlv,
            camera.SETUP_TYPES['VIDEO_SSRC'], struct.pack('<I', video_ssrc),
            camera.SETUP_TYPES['AUDIO_SSRC'], struct.pack('<I', audio_ssrc),
            to_base64=True
            )
        
        # print("response_tlv: %s" % (str(response_tlv)))

        self.sessions[session_id] = {
            'id': session_id,
            'stream_idx': stream_idx,
            'is_ipv6': is_ipv6,
            'ip_ver': 'IP6' if is_ipv6 else 'IP4',
            'address': address,
            'v_port': target_video_port,
            'v_return_port': video_return_port,
            'v_srtp_key': to_base64_str(video_master_key + video_master_salt),
            'v_ssrc': video_ssrc,
            'a_port': target_audio_port,
            'a_return_port': audio_return_port,
            'a_srtp_key': to_base64_str(audio_master_key + audio_master_salt),
            'a_ssrc': audio_ssrc
        }

        self._management[stream_idx].get_characteristic('SetupEndpoints').set_value(response_tlv)

    async def stop(self):
        """Stop all streaming sessions."""
        await asyncio.gather(*(
            self.stop_stream(session_info) for session_info in self.sessions.values()))

    # ### For client extensions ###

    async def start_stream(self, session_info, stream_config):
        """Start a new stream with the given configuration.

        This method can be implemented to start a new stream. Any specific information
        about the started stream can be persisted in the ``session_info`` argument.
        The same will be passed to ``stop_stream`` when the stream for this session
        needs to be stopped.

        The default implementation starts a new process with the command in
        ``self.start_stream_cmd``, formatted with the ``stream_config``.

        :param session_info: Contains information about the current session. Can be used
            for session storage. Available keys:
            - id - The session ID.
        :type session_info: ``dict``
        :param stream_config: Stream configuration, as negotiated with the HAP client.
            Implementations can only use part of these. Available keys:
            General configuration:
                - address - The IP address from which the camera will stream
                - v_port - Remote port to which to stream video
                - v_srtp_key - Base64-encoded key and salt value for the
                    AES_CM_128_HMAC_SHA1_80 cipher to use when streaming video.
                    The key and the salt are concatenated before encoding
                - a_port - Remote audio port to which to stream audio
                - a_srtp_key - As v_srtp_params, but for the audio stream.
            Video configuration:
                - v_profile_id - The profile ID for the H.264 codec, e.g. baseline.
                    Refer to ``VIDEO_CODEC_PARAM_PROFILE_ID_TYPES``.
                - v_level - The level in the profile ID, e.g. 3:1.
                    Refer to ``VIDEO_CODEC_PARAM_LEVEL_TYPES``.
                - width - Video width
                - height - Video height
                - fps - Video frame rate
                - v_ssrc - Video synchronisation source
                - v_payload_type - Type of the video codec
                - v_max_bitrate - Maximum bit rate generated by the codec in kbps
                    and averaged over 1 second
                - v_rtcp_interval - Minimum RTCP interval in seconds
                - v_max_mtu - MTU that the IP camera must use to transmit
                    Video RTP packets.
            Audio configuration:
                - a_bitrate - Whether the bitrate is variable or constant
                - a_codec - Audio codec
                - a_comfort_noise - Wheter to use a comfort noise codec
                - a_channel - Number of audio channels
                - a_sample_rate - Audio sample rate in KHz
                - a_packet_time - Length of time represented by the media in a packet
                - a_ssrc - Audio synchronisation source
                - a_payload_type - Type of the audio codec
                - a_max_bitrate - Maximum bit rate generated by the codec in kbps
                    and averaged over 1 second
                - a_rtcp_interval - Minimum RTCP interval in seconds
                - a_comfort_payload_type - The type of codec for comfort noise

        :return: True if and only if starting the stream command was successful.
        :rtype: ``bool``
        """
        self.log.debug(
            '[%s] Starting stream with the following parameters: %s',
            session_info['id'],
            stream_config
        )

        cmd = self.start_stream_cmd.format(**stream_config).split()

        ffmpeg_process = FfmpegProcess(
            process_name = 'camera',
            ffmpeg_args = cmd,
            ffmpeg_debug = True,
            log = self.log.getChild('FfmpegProcess'),
            ffmpeg_log = self.log.getChild('ffmpeg')
        )

        await ffmpeg_process.start()

        if ffmpeg_process.process is None:
            return False

        session_info['process'] = ffmpeg_process.process

        self.log.info(
            '[%s] Started stream process - PID %d',
            session_info['id'],
            ffmpeg_process.process.pid
        )

        return await self.start_audio_return_stream(session_info, stream_config)

        return True


    async def start_audio_return_stream(self, session_info, stream_config):

        self.log.debug(
            '[%s] Starting audio return stream with the following parameters: %s',
            session_info['id'],
            stream_config
        )

        if '{sdp_filename}' in self.start_audio_return_stream_cmd:

            stream_config['sdp_filename'] = "speaker_%s.sdp" % (str(session_info['id']))

            await self.__create_sdp_file(stream_config)

        cmd = self.start_audio_return_stream_cmd.format(**stream_config).split()

        ffmpeg_process = FfmpegProcess(
            process_name = 'audio_return_stream',
            ffmpeg_args = cmd,
            ffmpeg_debug = True,
            log = self.log.getChild('FfmpegProcess'),
            ffmpeg_log = self.log.getChild('ffmpeg'),
            enable_stdin = True
        )

        await ffmpeg_process.start()

        if ffmpeg_process.process is None:
            return False

        session_info['audio_return_process'] = ffmpeg_process.process

        self.log.info(
            '[%s] Started audio return stream process - PID %d',
            session_info['id'],
            ffmpeg_process.process.pid
        )

        if '{sdp_filename}' not in self.start_audio_return_stream_cmd:
        
            sdp_content = self.audio_return_stream_sdp.format(**stream_config)

            self.log.debug(
                '[%s] Audio return stream sdp: %s',
                session_info['id'],
                sdp_content
            )

            await ffmpeg_process.write_stdin(sdp_content)

        return True
    

    async def __create_sdp_file(self, stream_config: dict):

        sdp_content = self.audio_return_stream_sdp.format(**stream_config)

        self.log.debug("Create sdp file: %s" % (str(sdp_content)))

        # with open(self.sdp_filename, 'w') as file:
        #     file.write(sdp_content)

        async with aiofiles.open(stream_config['sdp_filename'], 'w') as file:
            await file.write(sdp_content)

    async def stop_audio_return_stream(self, session_info: dict):

        session_id = session_info['id']
        ffmpeg_process = session_info.get('audio_return_process')
        if ffmpeg_process:
            self.log.info('[%s] Stopping audio return stream.' % (str(session_id)))
            try:
                ffmpeg_process.terminate()
                try:
                    async with async_timeout.timeout(2.0):
                        _, stderr = await ffmpeg_process.communicate()
                    self.log.debug('Audio return stream command stderr: %s', stderr.decode('utf-8'))
                except:
                    pass
            except ProcessLookupError as err:
                self.log.error('[%s] stop_audio_return_stream -> ProcessLookupError' % (str(session_id)))
            except asyncio.TimeoutError:
                self.log.error(
                    'Timeout while waiting for the audio return stream process '
                    'to terminate. Trying with kill.'
                )
                ffmpeg_process.kill()
                await ffmpeg_process.wait()
            self.log.debug('Audio return stream process stopped.')
        else:
            self.log.warning('No audio return process for session ID %s' % (str(session_id)))

    async def stop_stream(self, session_info: dict):

        session_id = session_info['id']
        ffmpeg_process = session_info.get('process')
        if ffmpeg_process:
            self.log.info('[%s] Stopping stream.' % (str(session_id)))
            try:
                ffmpeg_process.terminate()
                try:
                    async with async_timeout.timeout(2.0):
                        _, stderr = await ffmpeg_process.communicate()
                    self.log.debug('Stream command stderr: %s', stderr.decode('utf-8'))
                except:
                    pass
            except ProcessLookupError as err:
                self.log.error('[%s] stop_stream -> ProcessLookupError' % (str(session_id)))
            except asyncio.TimeoutError:
                self.log.error(
                    'Timeout while waiting for the stream process '
                    'to terminate. Trying with kill.'
                )
                ffmpeg_process.kill()
                await ffmpeg_process.wait()
            self.log.debug('Stream process stopped.')
        else:
            self.log.warning('No process for session ID %s' % (str(session_id)))

        

    async def reconfigure_stream(self, session_info, stream_config):
        """Reconfigure the stream so that it uses the given ``stream_config``.

        :param session_info: The session object for the session that needs to
            be reconfigured. Available keys:
            - id - The session id.
        :type session_id: ``dict``

        :return: True if and only if the reconfiguration is successful.
        :rtype: ``bool``
        """
        await self.start_stream(session_info, stream_config)

    # def get_snapshot(self, image_size):  # pylint: disable=unused-argument
    #     """Return a jpeg of a snapshot from the camera.

    #     Overwrite to implement getting snapshots from your camera.

    #     :param image_size: ``dict`` describing the requested image size. Contains the
    #         keys "image-width" and "image-height"
    #     """
    #     with open(os.path.join(RESOURCE_DIR, 'snapshot.jpg'), 'rb') as fp:
    #         return fp.read()


    def get_supported_rtp_config(self, support_srtp):
        """Return a tlv representation of the RTP configuration we support.

        SRTP support allows only the AES_CM_128_HMAC_SHA1_80 cipher for now.

        :param support_srtp: True if SRTP is supported, False otherwise.
        :type support_srtp: bool
        """
        if support_srtp:
            crypto = SRTP_CRYPTO_SUITES['AES_CM_128_HMAC_SHA1_80']
        else:
            crypto = SRTP_CRYPTO_SUITES['NONE']
        return tlv.encode(camera.RTP_CONFIG_TYPES['CRYPTO'], crypto, to_base64=True)

    def get_supported_video_stream_config(self, video_params):
        """Return a tlv representation of the supported video stream configuration.

        Expected video parameters:
            - codec
            - resolutions

        :param video_params: Supported video configurations
        :type video_params: dict
        """
        codec_params_tlv = tlv.encode(
            camera.VIDEO_CODEC_PARAM_TYPES['PACKETIZATION_MODE'],
            camera.VIDEO_CODEC_PARAM_PACKETIZATION_MODE_TYPES['NON_INTERLEAVED'])

        codec_params = video_params['codec']
        for profile in codec_params['profiles']:
            codec_params_tlv += \
                tlv.encode(camera.VIDEO_CODEC_PARAM_TYPES['PROFILE_ID'], profile)

        for level in codec_params['levels']:
            codec_params_tlv += \
                tlv.encode(camera.VIDEO_CODEC_PARAM_TYPES['LEVEL'], level)

        attr_tlv = b''
        for resolution in video_params['resolutions']:
            res_tlv = tlv.encode(
                camera.VIDEO_ATTRIBUTES_TYPES['IMAGE_WIDTH'], struct.pack('<H', resolution[0]),
                camera.VIDEO_ATTRIBUTES_TYPES['IMAGE_HEIGHT'], struct.pack('<H', resolution[1]),
                camera.VIDEO_ATTRIBUTES_TYPES['FRAME_RATE'], struct.pack('<H', resolution[2]))
            attr_tlv += tlv.encode(camera.VIDEO_TYPES['ATTRIBUTES'], res_tlv)

        config_tlv = tlv.encode(camera.VIDEO_TYPES['CODEC'], camera.VIDEO_CODEC_TYPES['H264'],
                                camera.VIDEO_TYPES['CODEC_PARAM'], codec_params_tlv)

        return tlv.encode(camera.SUPPORTED_VIDEO_CONFIG_TAG, config_tlv + attr_tlv,
                          to_base64=True)

    def get_supported_audio_stream_config(self, audio_params):
        """Return a tlv representation of the supported audio stream configuration.

        iOS supports only AACELD and OPUS

        Expected audio parameters:
        - codecs
        - comfort_noise

        :param audio_params: Supported audio configurations
        :type audio_params: dict
        """
        has_supported_codec = False
        configs = b''
        for codec_param in audio_params['codecs']:
            param_type = codec_param['type']
            if param_type == 'OPUS':
                has_supported_codec = True
                codec = camera.AUDIO_CODEC_TYPES['OPUS']
                bitrate = camera.AUDIO_CODEC_PARAM_BIT_RATE_TYPES['VARIABLE']
            elif param_type == 'AAC-eld':
                has_supported_codec = True
                codec = camera.AUDIO_CODEC_TYPES['AACELD']
                bitrate = camera.AUDIO_CODEC_PARAM_BIT_RATE_TYPES['VARIABLE']
            else:
                self.log.warning('Unsupported codec %s', param_type)
                continue

            param_samplerate = codec_param['samplerate']
            if param_samplerate == 8:
                samplerate = camera.AUDIO_CODEC_PARAM_SAMPLE_RATE_TYPES['KHZ_8']
            elif param_samplerate == 16:
                samplerate = camera.AUDIO_CODEC_PARAM_SAMPLE_RATE_TYPES['KHZ_16']
            elif param_samplerate == 24:
                samplerate = camera.AUDIO_CODEC_PARAM_SAMPLE_RATE_TYPES['KHZ_24']
            else:
                self.log.warning('Unsupported sample rate %s', param_samplerate)
                continue

            param_tlv = tlv.encode(camera.AUDIO_CODEC_PARAM_TYPES['CHANNEL'], b'\x01',
                                   camera.AUDIO_CODEC_PARAM_TYPES['BIT_RATE'], bitrate,
                                   camera.AUDIO_CODEC_PARAM_TYPES['SAMPLE_RATE'], samplerate)
            config_tlv = tlv.encode(camera.AUDIO_TYPES['CODEC'], codec,
                                    camera.AUDIO_TYPES['CODEC_PARAM'], param_tlv)
            configs += tlv.encode(camera.SUPPORTED_AUDIO_CODECS_TAG, config_tlv)

        if not has_supported_codec:
            self.log.warning('Client does not support any audio codec that iOS supports.')

            codec = camera.AUDIO_CODEC_TYPES['OPUS']
            bitrate = camera.AUDIO_CODEC_PARAM_BIT_RATE_TYPES['VARIABLE']
            samplerate = camera.AUDIO_CODEC_PARAM_SAMPLE_RATE_TYPES['KHZ_24']

            param_tlv = tlv.encode(
                camera.AUDIO_CODEC_PARAM_TYPES['CHANNEL'], b'\x01',
                camera.AUDIO_CODEC_PARAM_TYPES['BIT_RATE'], bitrate,
                camera.AUDIO_CODEC_PARAM_TYPES['SAMPLE_RATE'], samplerate)

            config_tlv = tlv.encode(camera.AUDIO_TYPES['CODEC'], codec,
                                    camera.AUDIO_TYPES['CODEC_PARAM'], param_tlv)

            configs = tlv.encode(camera.SUPPORTED_AUDIO_CODECS_TAG, config_tlv)

        comfort_noise = byte_bool(
                            audio_params.get('comfort_noise', False))
        audio_config = to_base64_str(
                        configs + tlv.encode(camera.SUPPORTED_COMFORT_NOISE_TAG, comfort_noise))
        return audio_config

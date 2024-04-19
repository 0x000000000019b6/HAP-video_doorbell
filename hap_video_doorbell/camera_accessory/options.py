from pyhap import camera, util

CAMERA_OPTIONS = {
    "stream_count": 10,
    "video": {
        "codec": {
            "profiles": [
                camera.VIDEO_CODEC_PARAM_PROFILE_ID_TYPES["BASELINE"],
                camera.VIDEO_CODEC_PARAM_PROFILE_ID_TYPES["MAIN"],
                camera.VIDEO_CODEC_PARAM_PROFILE_ID_TYPES["HIGH"]
            ],
            "levels": [
                camera.VIDEO_CODEC_PARAM_LEVEL_TYPES['TYPE3_1'],
                camera.VIDEO_CODEC_PARAM_LEVEL_TYPES['TYPE3_2'],
                camera.VIDEO_CODEC_PARAM_LEVEL_TYPES['TYPE4_0'],
            ],
        },
        "resolutions": [
            # Width, Height, framerate
            [1920, 1080, 30],
            [1280, 960, 30],
            [1280, 720, 30],
            [1024, 768, 30],
            [640, 480, 30],
            [640, 360, 30],
            [480, 360, 30],
            [480, 270, 30],
            [320, 240, 30],
            [320, 240, 15], # Required for Apple Watch
            [320, 180, 30],
        ],
    },
    "audio": {
        "codecs": [
            # {
            #     'type': 'OPUS',
            #     'samplerate': 24,
            # },
            {
                'type': 'AAC-eld',
                'samplerate': 16
            }
        ],
    },
    "srtp": True,
    "address": util.get_local_address(), 
    "start_stream_cmd": (
        '/bin/ffmpeg -re '

        '-f video4linux2 -i /dev/video0 '
        '-f alsa -i hw:1,0 '

        '-map 0:v '
        '-threads 4 '
        '-vcodec libx264 '
        '-pix_fmt yuv420p -color_range mpeg -r {fps} -f rawvideo -preset ultrafast -tune zerolatency '
        '-vf scale={width}:{height} -b:v {v_max_bitrate}k -bufsize {v_max_bitrate}k '
        '-payload_type 99 -ssrc {v_ssrc} -f rtp '
        '-srtp_out_suite AES_CM_128_HMAC_SHA1_80 -srtp_out_params {v_srtp_key} '
        'srtp://{address}:{v_port}?rtcpport={v_port}&'
        'localrtcpport={v_port}&pkt_size=1316 '

        '-map 1:a '
        '-codec:a libfdk_aac -profile:a aac_eld '
        ' -flags +global_header '
        '-f null '
        '-ar {a_sample_rate}k -b:a {a_max_bitrate}k -ac {a_channel} '
        '-payload_type 110 -ssrc {a_ssrc} -f rtp '
        '-srtp_out_suite AES_CM_128_HMAC_SHA1_80 -srtp_out_params {a_srtp_key} '
        'srtp://{address}:{a_port}?rtcpport={a_port}&'
        'localrtcpport={a_port}&pkt_size=188 '

        '-progress pipe:1'

    ),
    "start_audio_return_stream_cmd": (
        '/bin/ffmpeg -re '

        '-hide_banner '
        '-protocol_whitelist pipe,file,udp,rtp,crypto '
        '-f sdp '
        '-c:a libfdk_aac '
        '-i pipe: '
        # '-i {sdp_filename} '
        '-f alsa default '

    ),
    "audio_return_stream_sdp": (
        "v=0\r\n"
        "o=- 0 0 IN {ip_ver} {address}\r\n"
        "s=Talk\r\n"
        "c=IN {ip_ver} {address}\r\n"
        "t=0 0\r\n"
        "m=audio {a_return_port} RTP/AVP 110\r\n"
        "b=AS:24\r\n"
        "a=rtpmap:110 MPEG4-GENERIC/16000/1\r\n"
        "a=rtcp-mux\r\n"  # FFmpeg ignores this, but might as well
        "a=fmtp:110 profile-level-id=1;mode=AAC-hbr;sizelength=13;indexlength=3;indexdeltalength=3; config=F8F0212C00BC00\r\n"
        "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{a_srtp_key}\r\n"
    )

}

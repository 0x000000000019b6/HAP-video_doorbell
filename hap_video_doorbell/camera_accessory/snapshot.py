
from dataclasses import dataclass, asdict
import asyncio
from logging import Logger
import subprocess
import io
from PIL import Image
from time import time

@dataclass
class SnapshotCache:
    image: bytes
    expiration_time: int

    def __post_init__(self):
        pass

    def get(self):
        return self.image

    def get_len(self):
        return len(self.image)
    
    def expired(self):
        return True if self.expiration_time <= int(time()) else False

class Snapshot:

    cmd = [
        "{ffmpeg}",
        "-re",
        "-f", "video4linux2", 
        "-ss", "0.9",
        "-i", "{dev_video}",
        "-vframes", "1",
        "-frames:v", "1",
        '-s', '{image_width}x{image_height}',
        "-f", "image2", "-",
        '-hide_banner',
        '-loglevel', 'error',
    ]

    def __init__(self,
                ffmpeg_path: str,
                dev_video: str,
                log: Logger,
                cache_timeout: int
                ) -> None:
        
        self.ffmpeg_path = ffmpeg_path
        self.dev_video = dev_video
        self.cache_timeout = cache_timeout
        
        self.lock = asyncio.Lock()

        self.log = log

        self.snapshots = {}

        self.last_update = 0

    def __format_cmd(self, image_size: dict) -> list:

        formated_cmd = []

        for param in self.cmd:

            if "{ffmpeg}" in param:
                param = param.replace("{ffmpeg}", self.ffmpeg_path)

            if "{dev_video}" in param:
                param =param.replace("{dev_video}", self.dev_video)

            if "{image_width}" in param:
                param =param.replace("{image_width}", str(image_size['image-width']))

            if "{image_height}" in param:
                param = param.replace("{image_height}", str(image_size['image-height']))

            formated_cmd.append(param)

        return formated_cmd

    async def __call__(self, image_size: dict) -> bytes:
        """Asynchronously return a jpeg of a snapshot from the camera in memory,
        using an asyncio lock to ensure thread safety.
        """

        key_name = "%sx%s" % (str(image_size['image-width']), str(image_size['image-height']))

        if key_name not in self.snapshots.keys() or self.snapshots[key_name].expired():

            self.log.debug("Get Snapshot -> size: %s" % (str(key_name)))
                
            async with self.lock:
                # The rest of your code for getting the snapshot
                try:

                    # homebridge cmd: ffmpeg -re -f video4linux2 -ss 0.9 -i /dev/video0 -vframes 1 -frames:v 1 -f image2 - -hide_banner -loglevel error

                    cmd = self.__format_cmd(image_size)
                    
                    self.log.debug("Snapshot command: %s" % (str(' '.join(cmd))))

                    # cmd = [
                    #     "/bin/ffmpeg",
                    #     "-re",
                    #     "-f", "video4linux2",
                    #     "-i", "/dev/video0",
                    #     "-s", "640x360",
                    #     "-update", "1",
                    #     "-vf", "fps=1",
                    #     "-f", "image2",
                    #     "-",
                    #     "-hide_banner",
                    #     "-loglevel", "error"
                    # ]

                    process = await asyncio.create_subprocess_exec(*cmd,
                            stdout=subprocess.PIPE, 
                            stderr=subprocess.PIPE,
                            limit=1024*10
                    )

                    stdout, stderr = await process.communicate()

                    if process.returncode != 0:
                            raise RuntimeError("ffmpeg command failed: %s" % (str(stderr.decode())))

                    # Store the image in PIL format and then convert to bytes
                    image = Image.open(io.BytesIO(stdout))

                    buffer = io.BytesIO()

                    image.save(buffer, format="JPEG")

                    width, height = image.size

                    self.log.debug("Snapshot image size: %sx%s" % (str(width),str(height)))

                    self.snapshots[key_name] = SnapshotCache(
                        image = buffer.getvalue(),
                        expiration_time = int(time()) + self.cache_timeout
                    )

                except Exception as err:
                    self.log.error("Snapshot error: %s" % (str(err)))
                    return b''

        else:
            self.log.debug("Get Snapshot from cache-> size: %s" % (str(key_name)))

        self.log.debug("Snapshot bytes size: %s" % (str(self.snapshots[key_name].get_len())))

        # Optionally, return the image as well
        return self.snapshots[key_name].get()
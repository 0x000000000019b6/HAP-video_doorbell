from ..utils.logger import Logger
import asyncio
import subprocess 
import logging

class FfmpegProcess:

    def __init__(self,
                process_name: str,
                ffmpeg_args: list,
                ffmpeg_debug: bool = False,
                log = Logger.getLogger('FfmpegProcess'),
                ffmpeg_log = Logger.getLogger('ffmpeg'),
                enable_stdin: bool = True,
                ) -> None:
        
        self.process_name = process_name

        self.ffmpeg_args = ffmpeg_args

        self.log = log

        self.ffmpeg_log = ffmpeg_log

        self.ffmpeg_debug = ffmpeg_debug

        self.enable_stdin = enable_stdin

        self.process: asyncio.subprocess.Process = None

    async def start(self):

        log_args = [
            '-loglevel', 
            'level%s' % (
                str('+verbose' if self.ffmpeg_debug == True else '')
                )
            ]

        # log_args += ['-progress', 'pipe:1']

        self.ffmpeg_args += log_args

        self.log.debug("[%s] Executing start stream command: '%s'" % (str(self.process_name), str(' '.join(self.ffmpeg_args))))

        try:

            self.process = await asyncio.create_subprocess_exec(*self.ffmpeg_args,
                    stdout = asyncio.subprocess.PIPE,
                    stderr = asyncio.subprocess.PIPE,
                    stdin = asyncio.subprocess.PIPE if self.enable_stdin == True else None,
                    limit = 1024
                    )
            
        except Exception as e:
            
            self.log.error('Failed to start streaming process because of error: %s', e)

        # if self.process is not None:

        if self.ffmpeg_debug == True:

            stderr_task = asyncio.create_task(self.__ffmpeg_subprocess_stream(self.process.stderr, self.__ffmpeg_subprocess_stderr_callback))

    async def __ffmpeg_subprocess_stream(self, stream, callback):
        while True:
            try:
                line = await stream.readline()
            except ValueError as err:
                pass

            if line:
                callback(line)
            else:
                break

        self.ffmpeg_log.debug("FFMPEG process stderr stream exit.")

    def __ffmpeg_subprocess_stderr_callback(self, line):
        decoded_line = str(line.decode()).replace('  ', '')

        level = logging.INFO

        if '[error]' in str(decoded_line):
            decoded_line = decoded_line.replace('[error]', '')
            level = logging.ERROR
        elif '[fatal]' in str(decoded_line):
            decoded_line = decoded_line.replace('[fatal]', '')
            level = logging.CRITICAL
        elif '[verbose]' in str(decoded_line):
            decoded_line = decoded_line.replace('[verbose]', '')
            level = logging.DEBUG
        elif '[warning]' in str(decoded_line):
            decoded_line = decoded_line.replace('[warning]', '')
            level = logging.WARNING
        else:
            decoded_line = decoded_line.replace('[info]', '')
            level = logging.INFO

        decoded_line = decoded_line.strip()

        self.ffmpeg_log.log(level, "[%s] %s" % (str(self.process_name), str(decoded_line)), stacklevel=2)

    async def write_stdin(self, input: str):

        data = input.encode()

        if self.ffmpeg_debug == True:

            self.ffmpeg_log.debug("Write stdin data: %s" % (str(data)))

        # stdout, stderr = await self.process.communicate(input=data)

        self.process.stdin.write(data = data)

        await self.process.stdin.drain()  # Ensure all data is sent
        self.process.stdin.close()  # Close stdin to indicate end of data
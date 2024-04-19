import logging

class Logger(logging.Logger):

    @classmethod
    def getLogger(cls, 
                  name: str, 
                  level: int | str = logging.DEBUG, 
                  console_level: int | str = logging.DEBUG, 
                  log_file: str | None = None,
                  file_level: int | str = logging.DEBUG, 
                  fmt: str = "%(asctime)s %(process)d %(processName)s %(threadName)s %(levelname)s %(name)s %(module)s.%(funcName)s:%(lineno)d # %(message)s"
                  ) -> logging.Logger:

        logger = cls(name = name)

        logger.setLevel(level)

        formatter = logging.Formatter(fmt)

        stream_handler = logging.StreamHandler()
        stream_handler.setLevel(console_level)
        stream_handler.setFormatter(formatter)

        logger.addHandler(stream_handler)

        if log_file is not None:

            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(file_level)
            file_handler.setFormatter(formatter)

            logger.addHandler(file_handler)

        return logger
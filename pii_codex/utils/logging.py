from time import time
import logging

logger = logging.getLogger()


def timed_operation(func):
    """
    Used to show execution time for function
    @param func:
    @return:
    """

    def wrapper_function(*args, **kwargs):
        """
        Logs the function execution time

        @param args:
        @param kwargs:
        @return:
        """
        start_time = time()
        result = func(*args, **kwargs)
        end_time = time()
        logger.info(f"{func.__name__!r} executed in {(end_time - start_time):.4f}s")
        return result

    return wrapper_function

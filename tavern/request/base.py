from abc import abstractmethod

from box import Box


class BaseRequest(object):
    @abstractmethod
    def run(self):
        """Run test"""

    @property
    @abstractmethod
    def request_vars(self) -> Box:
        """Get any extra variables used for this request"""

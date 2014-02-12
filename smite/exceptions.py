class ConnectionError(Exception):
    pass


class ClientTimeout(Exception):
    pass


class ServantBindError(Exception):
    pass


class MessageException(Exception):

    def __init__(self, message, traceback):
        super(MessageException, self).__init__(message)
        self.traceback = traceback

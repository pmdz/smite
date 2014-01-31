class Message(object):

    def __init__(self, method, *args, **kwargs):
        self.method = method
        self.args = args
        self.kwargs = kwargs

    def __repr__(self):
        return ('<Message(\'{}\', args={}, kwargs={})>'
                .format(self.method, self.args, self.kwargs))

    def __str__(self):
        return self.__repr__()

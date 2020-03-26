class Weakness(object):
    """ Common weakness object """

    def __init__(self, **attrs):
        self._attrs: set = set()

        for k, v in attrs.items():
            setattr(self, k, v)
            self._attrs.add(k)

    def to_dict(self) -> dict:
        """ Returns a dictionary of the Weakness """
        return {i: getattr(self, i, None) for i in self._attrs}

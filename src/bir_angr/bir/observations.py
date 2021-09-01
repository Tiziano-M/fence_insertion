import logging
from angr.state_plugins.plugin import SimStatePlugin

l = logging.getLogger(name=__name__)


class SimStateObservations(SimStatePlugin):
    def __init__(self, backer=None, accumulate=None):
        super(SimStateObservations, self).__init__()
        self._backer = backer if backer is not None else []
        self._accumulate = accumulate if accumulate is not None else Accumulate()

    def set_state(self, state):
         super(SimStateObservations, self).set_state(state)

    def append(self, obs):
        self._backer.append(obs)

    @property
    def list_obs(self):
        return self._backer

    @property
    def accumulate(self):
        return self._accumulate

    @property
    def accumulate_copy(self):
        return self._accumulate.copy()

    @SimStatePlugin.memo
    def copy(self, memo):   # pylint: disable=unused-argument
        return SimStateObservations(list(self._backer), self.accumulate_copy)



class Accumulate(object):
    def __init__(self, backer=None):
        self._backer = backer if backer is not None else []

    def append(self, obs):
        self._backer.append(obs)

    @property
    def list_obs(self):
        return self._backer

    @SimStatePlugin.memo
    def copy(self, memo):   # pylint: disable=unused-argument
        return Accumulate(list(self._backer))



from angr.sim_state import SimState
SimState.register_default('observations', SimStateObservations)

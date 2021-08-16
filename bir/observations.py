import logging
from angr.state_plugins.plugin import SimStatePlugin

l = logging.getLogger(name=__name__)


class SimStateObservations(SimStatePlugin):
    def __init__(self, backer=None):
        super(SimStateObservations, self).__init__()
        self._backer = backer if backer is not None else []

    def set_state(self, state):
         super(SimStateObservations, self).set_state(state)

    def get_list_obs(self):
        return self._backer

    def append(self, obs):
        self._backer.append(obs)

    @SimStatePlugin.memo
    def copy(self, memo):   # pylint: disable=unused-argument
        return SimStateObservations(list(self._backer))



from angr.sim_state import SimState
SimState.register_default('observations', SimStateObservations)

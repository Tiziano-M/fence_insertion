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

    def merge(self, others, merge_conditions, common_ancestor=None): # pylint: disable=unused-argument
        def check_obs_in_list(single_obs, list_obs):
            check = False
            for lo in list_obs:
                if (single_obs[0] == lo[0] and 
                    single_obs[1].structurally_match(lo[1]) and 
                    any(sos.structurally_match(los) for sos in single_obs[2] for los in lo[2])):
                    check = True
                    break
            return check


        for other in others:
            for o in other.list_obs:
                if not check_obs_in_list(o, self.list_obs):
                    self.list_obs.append(o)

        return True

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

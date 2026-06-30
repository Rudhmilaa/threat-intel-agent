from storage.es import StingarES
from storage.db import StingarDB
from storage.kibana import StingarKibana

from foundation.amun import AmunFoundation
from foundation.conpot import ConpotFoundation
from foundation.cowrie import CowrieFoundation
from foundation.dionaea import DionaeaFoundation
from foundation.glastopf import GlastopfFoundation
from foundation.rdphoney import RDPHoneyFoundation
from foundation.uhp import UHPFoundation
from foundation.generic import GenericFoundation


builders = {'amun': AmunFoundation(),
            'conpot': ConpotFoundation(),
            'cowrie': CowrieFoundation(),
            'dionaea': DionaeaFoundation(),
            'glastopf': GlastopfFoundation(),
            'rdphoney': RDPHoneyFoundation(),
            'uhp': UHPFoundation()}


es = StingarES()
db = StingarDB()
kb = StingarKibana()

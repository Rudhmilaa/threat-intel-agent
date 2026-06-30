"""
Foundation Builder Registration for Apiarist.

This module registers all honeypot-specific builders and provides
a fallback to the generic builder for unknown honeypot types.
"""

from .base import BaseFoundation
from .cowrie import CowrieFoundation
from .dionaea import DionaeaFoundation
from .conpot import ConpotFoundation
from .glastopf import GlastopfFoundation
from .amun import AmunFoundation
from .rdphoney import RDPHoneyFoundation
from .uhp import UHPFoundation
from .generic import GenericFoundation

# Register all builders
builders = {
    'cowrie': CowrieFoundation(),
    'dionaea': DionaeaFoundation(),
    'conpot': ConpotFoundation(),
    'glastopf': GlastopfFoundation(),
    'amun': AmunFoundation(),
    'rdphoney': RDPHoneyFoundation(),
    'uhp': UHPFoundation(),
}

def get_builder(hp_type):
    """
    Get builder for honeypot type, fallback to generic builder.
    
    Args:
        hp_type: Honeypot type
        
    Returns:
        Builder instance
    """
    return builders.get(hp_type, GenericFoundation())

# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/imaging_step_init.py
# Compiled at: 2019-02-15 12:42:10
import imaging_context
from imaging_step import ImagingStepNodeTask
from imaging_step_init_ipmi import ImagingStepInitIPMI
from imaging_step_init_cvm import ImagingStepInitCVM

class ImagingStepInitFactory(ImagingStepNodeTask):
    """
    Factory class to spawn ImagingStepInit object based on current
    imaging context.
    """
    class_mapping = {imaging_context.FIELD_IPMI: ImagingStepInitIPMI, 
       imaging_context.FACTORY: ImagingStepInitIPMI, 
       imaging_context.FIELD_VM: ImagingStepInitCVM}

    def __new__(cls, *args, **kargs):
        mapping = ImagingStepInitFactory.class_mapping
        assert imaging_context.get_context() in mapping, 'Imaging context %s is not supported' % imaging_context.get_context()
        cls = mapping[imaging_context.get_context()]
        instance = cls(*args, **kargs)
        return instance
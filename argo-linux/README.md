# V4V

Interdomain communications driver that interfaces the v4v hypervisor extensions
in OpenXT. The interfacing is done directly through hypercalls and events are
raised using a dedicated VIRQ. All guest to guest communications is brokered
through the hypervisor.

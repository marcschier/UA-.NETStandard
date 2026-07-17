# Opc.Ua.Robotics

Shared foundation for the **OPC 40010 Robotics** companion specification
(`MotionDeviceSystem` → `MotionDevice` → `Axis`).

The Robotics NodeSet and its required Industrial Automation (IA) base model are
carried here as embedded NodeSet2 XML and imported at **runtime** into a server
node manager (`RoboticsNodeSets.ImportInto`) rather than source-generated — the
Robotics model relies on base state-machine/method types whose generated proxies
are not all present in this Core, so runtime import loads the full, faithful type
structure. A consumer builds instances from `BaseObjectState` plus the numeric
type NodeIds in `RoboticsModel` (`MotionDeviceSystemType`, `MotionDeviceType`,
`AxisType`, `ControllerType`).

Pair it with **Opc.Ua.Robotics.Server** (address-space building) and
**Opc.Ua.Robotics.Client**, and with the draft **Opc.Ua.OpenUsd** model to render
a live robot-cell twin.

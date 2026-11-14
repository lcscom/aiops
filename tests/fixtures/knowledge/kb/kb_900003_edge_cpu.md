# NSX Edge datapath CPU usage is high (edge_health.edge_datapath_cpu_high)

**Article ID:** 900003
**Updated On:** 2026-05-02
**Products:** VMware NSX
**URL:** https://knowledge.broadcom.com/external/article/900003

## Issue/Introduction
The alarm `edge_health.edge_datapath_cpu_high` is raised and north-south traffic through the Tier-0 gateway is dropped.

## Environment
VMware NSX 4.2.x
VMware NSX 4.1.x

## Cause
The Edge node VM is undersized (MEDIUM form factor) for the traffic profile, or the Edge VM shares a congested ESXi host.

## Resolution
1. On the Edge node CLI check datapath CPU: `get dataplane cpu stats`
2. Check flow cache hit rate: `get dataplane flow-cache stats`
3. [Change] Move the Edge VM to a less loaded host or resize the Edge to LARGE form factor via NSX Manager > System > Fabric > Nodes > Edge Transport Nodes.

## Workaround
Fail over the Tier-0 service router to the standby Edge in the same Edge cluster.

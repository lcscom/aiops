---
title: Avi Service Engine marked down after heartbeat failure (SE_DOWN)
kb: "900004"
product: NSX Advanced Load Balancer (Avi)
versions: [30.2, 31.1]
---
## Symptoms
The Controller generates event `SE_DOWN` and `SE_HEARTBEAT_FAILURE` and virtual services placed on the SE move to another SE.

## Cause
The Controller did not receive heartbeats from the Service Engine for 30 seconds because of management network loss or the ESXi host failure.

## Resolution
1. In the Controller UI open Infrastructure > Cloud Resources > Service Engine and check the SE status reason.
2. Verify the SE management vNIC connectivity from the Controller: `ping <SE mgmt IP>`
3. Check the ESXi host running the SE VM in vCenter.

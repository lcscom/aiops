---
title: Service Engine High Availability
url: https://techdocs.broadcom.com/us/en/vmware-security-load-balancing/avi-load-balancer/avi-load-balancer/31-1/configuration-guide/se-high-availability.html
---
# Service Engine High Availability

## Elastic HA N+M mode
In N+M mode, virtual services are placed on N service engines and M service engines of buffer capacity are reserved.
When a Service Engine fails (event SE_DOWN), its virtual services are re-placed on the buffer capacity.

### Configuring the buffer
Navigate to Infrastructure > Cloud Resources > Service Engine Group > High Availability & Placement, set **Buffer Service Engines**.

## Active/Standby mode
Each virtual service is placed on two Service Engines; the standby takes over within seconds.

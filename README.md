# Homelab-setup
This repo is for fully dpeloying my homelab services across multiple on-prem and cloud based machines.
On-Prem includes a Dell E7270 Laptop and a Raspberry Pi 4 8gb that are a failover pair via keepalived. 
Oracle Cloud hosts a virtual machine acting as a tunnel for on-prem hosted services, protected by the OCI Load Balancer and WAF.

The mission statement of this is to self-host paid-for cloud services in a secure manner.

The project tasklist is here: https://github.com/users/liamj-f/projects/3

## List of Services
Those in brackets are not yet fully deployed/Tested

### E7270
- Keepalived
  - Pihole
  - Nginx Proxy Manager
  - Nebula-Sync
  - Rathole-Client
- (Nextcloud)
- Postgres
- PgAdmin
- Portainer-Agent
- (GrampsWeb)
- (Frigate)
- Traefik/WHOAMI 

### RPI4
- Keepalived
  - Pihole
  - Nginx Proxy Manager
  - Nebula-Sync
  - Rathole-Client
- Portainer
- DuckDNS
- (Homepage)

### LJFCloud 
- Portainer-Agent
- Nginx Proxy Manager
- Dovetrek-PWA
- DuckDNS

## Final Architecture

```mermaid
flowchart TB
classDef lan fill:#ffd6d6,stroke:#c92a2a,stroke-width:2px,color:#000

    internet((Public
            Internet)) --> pbdns((Porkbun
                                Nameserver)) & duck_ns((DuckDNS
            Nameserver))

    subgraph OCI["Oracle Cloud"]
        direction TB
        lb([Load Balancer
                **10.0.0.6**])
        waf([Web Application Firewall])
        ocicerts([OCI Certificate Store])
        nsg([Network Security Groups])

        subgraph ljfvm[ljfcloud VM]
            direction LR
            portainer_a1(Portainer Agent)
            ociddns("OCI Dynamic IP Updater")
            ociCertUp("OCI Certificate Updater")
            dvtrk(Dovetrek-PWA)
            duckdns3(DuckDNS)
            nginx3(Nginx-Proxy-Manager) -->|"*.14monarch/*.hannah/*.liam/*.oci .james-fagg.uk"| rathole_s(Rathole Server)
            nginx3 -->|dovetrek.oci.james-fagg.uk| dvtrk
        end

        lb -.-> waf --> nginx3
        nginx3 -.->|Grabs CertBot certs| ociCertUp -.->|Uploads shared multi-SAN cert| ocicerts -.->|Serves SSL| lb
        ociddns -.->|Whitelists home dynamic IP| nsg
        ociddns -.->|Whitelists home dynamic IP| waf

    end
    style OCI lan

    subgraph monarch14[14monarch]

        ka_vip([Keepalived Virtual IP])

        subgraph rpi4[Raspberry Pi 4]

            subgraph ka1[Keepalived]
                ka_c1(Keepalived Container)
                pihole1(Pihole)
                neb_s1(Nebula-Sync)
                nginx1(Nginx-Proxy-Manager)
                rathole_c1(Rathole Client)
            end

            portainer_s(Portainer Server)
            duckdns1(DuckDNS)
            f2b1(Fail2Ban)
            codeserver(Code-Server)
            authelia(Authelia)
            authelia_kv(Valkey)
            authelia --> authelia_kv

            rathole_c1 --> nginx1 --> portainer_s & pihole1 & codeserver & authelia
        end

        subgraph e7270[E7270]
            direction LR
            f2b2(Fail2Ban)
            subgraph ka2[Keepalived]
                pihole2(Pihole)
                neb_s2(Nebula-Sync)
                nginx2(Nginx-Proxy-Manager)
                rathole_c2(Rathole Client)
                ka_c2(Keepalived Container)
            end
            portainer_a2(Portainer Agent)

            subgraph data_e7270[Databases]
                postgres[(Postgres)]
                pgadmin(PgAdmin)
                pgadmin --- postgres
            end

            NxtCld(NextCloud)
            gramps(GrampsWeb)
            avalon(Avalon)
            whoami(WHOAMI)

            rathole_c2 --> nginx2 --> NxtCld & gramps & avalon & whoami & pihole2
            NxtCld -.-> postgres
            gramps -.-> postgres
            avalon -.-> postgres
        end

    end

    rathole_s ----> ka_vip
    portainer_a1 -.->|managed by| portainer_s
    ka_vip --> rathole_c2 & rathole_c1
    nginx1 -.->|auth_request| authelia
    pbdns --> lb
    duck_ns ~~~ duckdns3
    duckdns3 -.->|14monarch.duckdns.org| duck_ns
    duck_ns <-.-> ociddns
    f2b1 -.->|"reads /opt/f2b-logs, bans via API"| waf
    f2b2 -.->|"reads /opt/f2b-logs, bans via API"| waf

 %% Kept off this diagram to preserve the RPI4/E7270 side-by-side layout
 %% (any direct edge between the two hosts forces dagre to stack them):
 %% - keepalived VRRP heartbeat (ka_c1 <-> ka_c2)
 %% - Nebula-Sync (neb_s1 <-> neb_s2) - each still sits next to its own Pihole
 %% - Portainer Agent (E7270) is also managed by the Portainer Server (RPI4)
 %% - E7270's Nginx-Proxy-Manager also forward-auths through Authelia (RPI4)
 %% - RPI4's own DuckDNS instance also registers 14monarch.duckdns.org
```


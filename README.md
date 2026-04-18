# Homelab-setup
This repo is for fully dpeloying my homelab services across multiple on-prem and cloud based machines.
On-Prem includes a Dell E7270 Laptop and a Raspberry Pi 4 8gb that are a failover pair via keepalived. 
Oracle Cloud hosts a virtual machine acting as a tunnel for on-prem hosted services, protected by the OCI Load Balancer and WAF.

The mission statement of this is to self-host paid-for cloud services in a secure manner.

The project tasklist is here: https://github.com/users/liamj-f/projects/3

## List of Services
Those in brackets are not yet fully deployed/Tested
### RPI4 & E7270 via Keepalived
- Pihole
- Nginx Proxy Manager
- Nebula-Sync
- Rsync
- Keepalived
- (Rathole-Client)

### E7270
- (Nextcloud)
- (PostGres)
- Adminer
- Portainer-Agent
- (GrampsWeb)
- (Frigate)
- Traefik/WHOAMI 

### RPI4
- Portainer
- DuckDNS
- Homepage

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
        %%        lb@{ img: "https://static.oracle.com/cdn/fnd/gallery/2607.0.1/images/ico-load-balancer.svg", label: "OCI Load balancer",pos: "b", constraint: "on" }
        lb([Load Balancer
                **10.0.0.6**]) 
        waf([Web Application Firewall])
        ocicerts([OCI Certificate Store]) 
        nsg([Network Security Groups]) 

        subgraph ljfvm[ljfcloud VM]
            direction LR
            portainer_a1(Portainer Agent)
            ociddns("OCI Dynamic IP Updater") 
            dvtrk(Dovetrek-PWA)
            ociCertUp("OCI Certificate Updater")
            nginx3(Nginx-Proxy-Manager) -->|*.14monarch.james-fagg.uk| rathole_s(Rathole Server)
            nginx3 -->|dovetrek.oci.james-fagg.uk| dvtrk
        end

        lb -.-> waf --> nginx3
        nginx3 -.->|Grabs CertBot certs| ociCertUp -.->|Uploads Certs| ocicerts -.->|Serves SSL| lb
        
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
                rsync1(RSync)
                rathole_c1(Rathole Client)
            end

            portainer_s(Portainer Server)
            adminer(Adminer)
            duckdns(DuckDNS)
            rathole_c1(Rathole Client) --> nginx1 --> portainer_s & pihole1 & adminer  
        end

        subgraph e7270[E7270]
            direction LR
            f2b(Fail2Ban)
            subgraph ka2[Keepalived]
                pihole2(Pihole)
                neb_s2(Nebula-Sync)
                nginx2(Nginx-Proxy-Manager)
                rsync2(RSync)
                rathole_c2(Rathole Client)
                ka_c2(Keepalived Container)
            end
            portainer_a2(Portainer Agent)
            
            NxtCld(NextCloud)
            gramps(GrampsWeb)
            rathole_c2(Rathole Client) -->  nginx2 --> NxtCld & gramps & pihole2
        end

    end

    rathole_s ----> ka_vip
    portainer_a1 & portainer_a2 -.-> portainer_s
    ka_vip -->  rathole_c2 & rathole_c1
    ka_c1 --- ka_c2
    pbdns --> lb
    duck_ns ~~~ duckdns -.->|14monarch.duckdns.org| duck_ns <-.-> ociddns
    ociddns -.->|whitelist| nsg
    waf ~~~ f2b -.->|Ban Action| waf

 %% https://static.oracle.com/cdn/fnd/gallery/2607.0.1/images/ico-load-balancer.svg
```


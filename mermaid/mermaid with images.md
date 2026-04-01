```mermaid
flowchart TB
    duck_ns((DuckDNS 
            Nameserver))
    internet((Public 
            Internet)) --> pbdns((Porkbun 
                                Nameserver))

    subgraph OCI
        direction TB
        lb@{ img: "https://static.oracle.com/cdn/fnd/gallery/2607.0.1/images/ico-load-balancer.svg", label: "OCI Load balancer",pos: "b", constraint: "on" }
        waf@{ img: "https://static.oracle.com/cdn/fnd/gallery/2607.0.1/images/ico-firewall.svg", label: "Web Application Firewall",pos: "b", constraint: "on" }
        ocicerts@{ img: "https://static.oracle.com/cdn/fnd/gallery/2607.0.1/images/ico-certification.svg", label: "OCI Certificate Store",pos: "b", constraint: "on" }
        nsg@{ img: "https://static.oracle.com/cdn/fnd/gallery/2607.0.1/images/ico-secure-subject-area.svg", label: "Network Security Groups", pos: "b", constraint: "on"}
        subgraph ljfvm[ljfcloud VM]
            direction LR
            portainer_a1@{ img: "https://gdm-catalog-fmapi-prod.imgix.net/ProductLogo/4e0a8fce-b626-4e46-b199-87c9333440ea.png", label: "Portainer Agent",pos: "b",constraint: "on"}
            fail3ban(Fail3Ban)
            oci-ddns(OCI Dynamic IP Updater)
            oci-cert-up(OCI Certificate Updater)
            nginx3@{ img: "https://nginxproxymanager.com/icon.png", label: "Nginx-Proxy-Manager",pos: "b", consraint: "on"} --*.14monarch.james-fagg.uk--> rathole_s(Rathole Server)
        end
            lb --> waf --> nginx3
            nginx3 --certbot--> oci-cert-up -->  ocicerts
    end

    subgraph monarch14[14monarch]
        
        ka_vip([Keepalived Virtual IP])

        subgraph rpi4[Raspberry Pi 4]
            subgraph ka1[Keepalived]
                ka_c1(Keepalived Container)
                pihole1@{ img: "https://www.clipartmax.com/png/small/296-2965097_network-wide-ad-blocking-via-your-own-linux-hardware-pihole-logo.png", label: "Pihole", pos: "b", constraint: "on"}
                neb_s1(Nebula-Sync)
                nginx1@{ img: "https://nginxproxymanager.com/icon.png", label: "Nginx-Proxy-Manager",pos: "b", consraint: "on"}
                rsync1(RSync)
            end
            portainer_s@{ img: "https://gdm-catalog-fmapi-prod.imgix.net/ProductLogo/4e0a8fce-b626-4e46-b199-87c9333440ea.png", label: "Portainer Server",pos: "b",  constraint: "on"}
            rathole_c1(Rathole Client)
            adminer(Adminer)
            duckdns(DuckDNS)
        end

        subgraph e7270[E7270]
            subgraph ka2[Keepalived]
                ka_c2(Keepalived Container)
                pihole2(Pihole)
                neb_s2(Nebula-Sync)
                nginx2@{ img: "https://nginxproxymanager.com/icon.png", label: "Nginx-Proxy-Manager",pos: "b", consraint: "on"}
                rsync2(RSync)
            end
            portainer_a2@{ img: "https://gdm-catalog-fmapi-prod.imgix.net/ProductLogo/4e0a8fce-b626-4e46-b199-87c9333440ea.png", label: "Portainer Agent",pos: "b", constraint: "on"}
            rathole_c2(Rathole Client)
            NxtCld(NextCloud)

        end

    end

    rathole_s ----> ka_vip
    ka_vip --> rathole_c1 & rathole_c2
    rathole_c1 --> nginx1
    rathole_c2 --> nginx2
    pbdns --> lb
    duck_ns ~~~~ duckdns -.-> duck_ns -.-> oci-ddns --"whitelist"--> nsg

 %%   OCI :T -- B: 14monarch
 %% https://static.oracle.com/cdn/fnd/gallery/2607.0.1/images/ico-load-balancer.svg
```


// ---------------------------------------------------------------
// Homelab topology data — same shape as the media-server-iac
// version, but describing Liam's actual hybrid on-prem/OCI setup.
//
// A few edges are best-guess based on what's known about the
// stack rather than a read of the actual compose files, so check
// the // ASSUMPTION comments below and adjust anything that's off.
// ---------------------------------------------------------------

/** Where the node physically or logically lives. */
export type HomelabNetwork = 'onprem' | 'oci' | 'tunnel' | 'bridge' | 'external';

export type HomelabKind =
  | 'compute'   // a physical or virtual host
  | 'network'   // DNS, reverse proxy, tunnel, VPN, WAF
  | 'app'       // a self-hosted application
  | 'ops'       // management / CI-CD / automation tooling
  | 'security'; // ban actions, access control

export interface HomelabNode {
  id: string;
  label: string;
  kind: HomelabKind;
  network: HomelabNetwork;
  /** Host-exposed port, where one exists. */
  port?: number;
  /** Short factual description shown in the detail panel. */
  blurb: string;
}

export interface HomelabEdge {
  from: string;
  to: string;
  /** Relationship label, e.g. 'API', 'VPN tunnel'. */
  label: string;
}

export const homelabNodes: HomelabNode[] = [
  {
    id: 'rpi4',
    label: 'rpi4',
    kind: 'compute',
    network: 'onprem',
    blurb:
      'Raspberry Pi 4 at 192.168.0.2. Portainer server and keepalived MASTER for the on-prem pair.',
  },
  {
    id: 'e7270',
    label: 'e7270',
    kind: 'compute',
    network: 'onprem',
    blurb:
      'Latitude E7270 at 192.168.0.4. Portainer agent and keepalived BACKUP — takes over if rpi4 drops.',
  },
  {
    id: 'pihole',
    label: 'Pi-hole',
    kind: 'network',
    network: 'onprem',
    port: 53,
    blurb:
      'DNS/DHCP, floating on the keepalived VIP at 192.168.0.5 so it survives either node going down.',
  },
  {
    id: 'npm-onprem',
    label: 'Nginx Proxy Manager (on-prem)',
    kind: 'network',
    network: 'onprem',
    port: 443,
    blurb: 'Reverse proxy for services on the home network.',
  },
  {
    id: 'rathole',
    label: 'rathole',
    kind: 'network',
    network: 'tunnel',
    blurb:
      'Tunnel client on-prem, connecting out to the rathole server on ljfcloud so home services get a public path without opening inbound ports. frp was evaluated as an alternative.',
  },
  {
    id: 'ljfcloud',
    label: 'ljfcloud (OCI VM)',
    kind: 'compute',
    network: 'oci',
    blurb: 'OCI free-tier VM at 145.241.244.229. Public entry point for the whole lab.',
  },
  {
    id: 'oci-lb-waf',
    label: 'OCI Load Balancer + WAF',
    kind: 'network',
    network: 'oci',
    blurb:
      'Fronts ljfcloud. Default-block policy, GB geo-allow, admin IP allowlist, plus a fail2ban-fed blocklist.',
  },
  {
    id: 'npm-oci',
    label: 'Nginx Proxy Manager (OCI)',
    kind: 'network',
    network: 'oci',
    port: 443,
    blurb: 'Reverse proxy on ljfcloud, sits behind the LB/WAF and in front of the rathole tunnel.',
  },
  {
    id: 'fail2ban',
    label: 'fail2ban',
    kind: 'security',
    network: 'oci',
    blurb: 'Watches for brute-force attempts and pushes bans into the OCI WAF blocklist.',
  },
  {
    id: 'oci-sec-automation',
    label: 'OCI security-list sync',
    kind: 'ops',
    network: 'oci',
    blurb:
      'Small Python container using the OCI SDK to keep the security list in sync with the current DDNS-resolved home IP.',
  },
  {
    id: 'wireguard',
    label: 'WireGuard',
    kind: 'network',
    network: 'external',
    blurb:
      'VPN back into the home network through the TP-Link router. Used by CI/CD pipelines that need to reach on-prem.',
  },
  {
    id: 'github-actions',
    label: 'GitHub Actions',
    kind: 'ops',
    network: 'external',
    blurb: 'CI/CD pipelines that deploy via the Portainer API across rpi4 and e7270.',
  },
  {
    id: 'portainer',
    label: 'Portainer',
    kind: 'ops',
    network: 'bridge',
    port: 9000,
    blurb: 'Container management UI — server on rpi4, agent on e7270.',
  },
  {
    id: 'porkbun-dns',
    label: 'Porkbun (DNS)',
    kind: 'network',
    network: 'external',
    blurb:
      'Registrar for james-fagg.uk. Dynamic DNS keeps a record pointed at the home connection via 14monarch.tplinkdns.com; also hosts the custom email DNS records.',
  },
  {
    id: 'mailserver',
    label: 'Mail server',
    kind: 'app',
    network: 'oci',
    blurb:
      'docker-mailserver on ljfcloud for james-fagg.uk mail. SPF/DKIM in place; DMARC and OCI port-25 outbound restrictions still being worked through.',
  },
  {
    id: 'grampsweb',
    label: 'GrampsWeb',
    kind: 'app',
    // ASSUMPTION: not stated where this runs — placed on-prem since it's
    // treated as a personal-data app. Move to 'oci' if it's actually on ljfcloud.
    network: 'onprem',
    blurb:
      'Genealogy app in Docker with a Postgres backend. Multi-tree setup, Redis networking and IPv6 issues resolved; still wants to send registration/admin email without a personal Gmail app password.',
  },
  {
    id: 'dovetrek',
    label: 'DoveTrek',
    kind: 'app',
    network: 'oci',
    blurb: 'Solid-foods tracking PWA, deployed to OCI.',
  },
];

export const homelabEdges: HomelabEdge[] = [
  { from: 'rpi4', to: 'e7270', label: 'keepalived VRRP (unicast)' },
  { from: 'rpi4', to: 'pihole', label: 'keepalived MASTER' },
  { from: 'e7270', to: 'pihole', label: 'keepalived BACKUP' },
  { from: 'portainer', to: 'rpi4', label: 'server' },
  { from: 'portainer', to: 'e7270', label: 'agent' },
  { from: 'github-actions', to: 'portainer', label: 'deploy · API' },
  { from: 'github-actions', to: 'wireguard', label: 'VPN access to home network' },
  { from: 'npm-onprem', to: 'rathole', label: 'tunnel client' },
  { from: 'rathole', to: 'ljfcloud', label: 'tunnel server' },
  { from: 'ljfcloud', to: 'npm-oci', label: 'reverse proxy' },
  { from: 'oci-lb-waf', to: 'npm-oci', label: 'fronts' },
  { from: 'fail2ban', to: 'oci-lb-waf', label: 'ban action' },
  { from: 'oci-sec-automation', to: 'oci-lb-waf', label: 'security list sync' },
  { from: 'porkbun-dns', to: 'npm-onprem', label: 'DDNS record → 14monarch.tplinkdns.com' },
  { from: 'npm-oci', to: 'mailserver', label: 'reverse proxy' },
  // ASSUMPTION: GrampsWeb reached via the on-prem proxy — adjust if it's
  // actually fronted by npm-oci instead.
  { from: 'npm-onprem', to: 'grampsweb', label: 'reverse proxy' },
  { from: 'npm-oci', to: 'dovetrek', label: 'reverse proxy' },
];

/** Display names for the network groupings drawn on the schematic. */
export const homelabNetworks: Record<HomelabNetwork, string> = {
  onprem: 'home network',
  oci: 'Oracle Cloud (OCI)',
  tunnel: 'rathole tunnel',
  bridge: 'docker bridge',
  external: 'external',
};
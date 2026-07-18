export interface Project {
  name: string;
  description: string;
  tags: string[];
  link?: string;
}

export const projects: Project[] = [
  {
    name: 'Homelab-setup',
    description:
      'Multi-site Docker infrastructure spanning a Keepalived failover pair on-prem (Dell E7270 + Raspberry Pi 4) and an Oracle Cloud VM acting as tunnel and WAF front door.',
    tags: ['Docker Compose', 'Keepalived', 'Rathole', 'OCI'],
    link: 'https://github.com/liamj-f/homelab-setup',
  },
  {
    name: 'OCI Cert Updater',
    description:
      'Python service that uploads Nginx Proxy Manager’s renewed Let’s Encrypt certificates to OCI’s Certificate Service so the OCI Load Balancer can serve current SSL.',
    tags: ['Python', 'OCI', 'Automation'],
  },
  {
    name: 'Dynamic IP Updater',
    description:
      'Python service that keeps an OCI Network Security Group whitelist synchronised with a dynamic home IP address.',
    tags: ['Python', 'OCI', 'Networking'],
  },
  {
    name: 'GrampsWeb Deployment',
    description:
      'Self-hosted genealogy application with a custom bootstrap script handling owner and family-tree provisioning.',
    tags: ['Docker', 'Postgres', 'Genealogy'],
  },
];

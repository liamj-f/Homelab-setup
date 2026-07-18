export interface StackGroup {
  category: string;
  items: string[];
}

export const stack: StackGroup[] = [
  {
    category: 'Data & Analytics',
    items: [
      'Data Warehousing (Kimball & Inmon)',
      'Power BI & Power Query',
      'Tableau',
      'SSRS / SSIS',
      'Azure Data Factory',
      'Databricks',
      'CosmosDB',
    ],
  },
  {
    category: 'Languages',
    items: ['T-SQL / MySQL / SparkSQL', 'Python', 'R', 'KQL', 'M Formula', 'VBA'],
  },
  {
    category: 'Practices',
    items: ['CI/CD Pipelines', 'ELT', 'Agile/Scrum', 'Data Governance'],
  },
  {
    category: 'Homelab',
    items: [
      'Docker & Docker Compose',
      'Nginx Proxy Manager',
      'Keepalived',
      'Portainer',
      'Traefik',
      'Pi-hole',
      'DuckDNS',
      'Rathole',
      'GitHub Actions / Portainer GitOps',
    ],
  },
];

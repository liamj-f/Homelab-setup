export interface ExperienceEntry {
  org: string;
  role: string;
  dates: string;
  bullets?: string[];
}

export const experience: ExperienceEntry[] = [
  {
    org: 'Allpay Ltd',
    role: 'Head of Data',
    dates: 'Mar 2026 – Present',
    bullets: [
      'Grew the data function into four areas: analytics, engineering, Power Platform, and database administration.',
      'Set data strategy and AI adoption direction, and brought data governance (lineage, cataloguing, classification) into regular practice.',
      'Chairs the Change Approval Board and acts as Incident Manager for major business/client-facing incidents.',
    ],
  },
  {
    org: 'Allpay Ltd',
    role: 'Data & Insights Manager',
    dates: 'Oct 2022 – Mar 2026',
  },
  {
    org: 'Allpay Ltd',
    role: 'Business Intelligence Analyst',
    dates: 'May 2020 – Oct 2022',
    bullets: [
      'Shifted the business to a Power BI-first analytics culture, moving off SSRS and Crystal Reports.',
      'Modelled data marts using Kimball methodology and slowly changing dimensions.',
      'Automated prepaid card reconciliation into a stored-procedure endpoint, saving the payments team ~2 hours/day.',
    ],
  },
  {
    org: 'Operose Health',
    role: 'Business Intelligence Analyst',
    dates: 'Apr 2018 – May 2020',
    bullets: [
      'Built clinician-facing dashboards for Forward Thinking Birmingham (under-25s mental health partnership) at Birmingham Children’s Hospital.',
      'Used R (network3d, rpart) to surface cyclical service usage patterns by diagnosis.',
    ],
  },
  { org: 'The Zinc Group', role: 'Client Services Administrator', dates: 'Jan 2017 – Apr 2018' },
  { org: 'The Zinc Group', role: 'Customer Account Manager', dates: 'Aug 2016 – Jan 2017' },
  { org: 'British Army', role: 'Officer Cadet, Wales Universities OTC', dates: 'Sep 2014 – Sep 2015' },
  {
    org: 'St John Ambulance',
    role: 'Emergency Medical Technician & District Training Officer',
    dates: 'Aug 2016 – Jan 2022',
  },
  {
    org: 'The Scout Association',
    role: 'Assistant Explorer Scout Leader (Volunteer)',
    dates: 'Aug 2016 – Current',
  },
];

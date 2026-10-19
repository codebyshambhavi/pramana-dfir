// Line icons for the investigator console, in the same thin outline style as the landing icons.
import type { ReactNode, SVGProps } from "react";

type IconProps = SVGProps<SVGSVGElement> & { size?: number | string };

const Icon = ({ size = 18, children, strokeWidth = 1.7, ...props }: IconProps & { children: ReactNode }) => (
  <svg
    width={size}
    height={size}
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth={strokeWidth}
    strokeLinecap="round"
    strokeLinejoin="round"
    aria-hidden="true"
    {...props}
  >
    {children}
  </svg>
);

export const Search = (p: IconProps) => (
  <Icon {...p}>
    <circle cx="11" cy="11" r="7" />
    <path d="m20 20-3.5-3.5" />
  </Icon>
);

export const ChevronDown = (p: IconProps) => (
  <Icon {...p}>
    <path d="m6 9 6 6 6-6" />
  </Icon>
);

export const ChevronLeft = (p: IconProps) => (
  <Icon {...p}>
    <path d="m15 6-6 6 6 6" />
  </Icon>
);

export const ChevronRight = (p: IconProps) => (
  <Icon {...p}>
    <path d="m9 6 6 6-6 6" />
  </Icon>
);

export const SortArrows = (p: IconProps) => (
  <Icon {...p}>
    <path d="m8 9 4-4 4 4M8 15l4 4 4-4" />
  </Icon>
);

export const Copy = (p: IconProps) => (
  <Icon {...p}>
    <rect x="8" y="8" width="12" height="12" rx="2" />
    <path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2" />
  </Icon>
);

export const Check = (p: IconProps) => (
  <Icon {...p}>
    <path d="m5 12.5 4.5 4.5L19 7.5" />
  </Icon>
);

export const MoreVertical = (p: IconProps) => (
  <Icon {...p} strokeWidth={2.6}>
    <path d="M12 5h.01M12 12h.01M12 19h.01" />
  </Icon>
);

export const Close = (p: IconProps) => (
  <Icon {...p}>
    <path d="M6 6l12 12M18 6 6 18" />
  </Icon>
);

export const CloudUpload = (p: IconProps) => (
  <Icon {...p}>
    <path d="M7 18a4.5 4.5 0 0 1-.5-9A6 6 0 0 1 18 8a4 4 0 0 1-.5 10" />
    <path d="M12 12v8M8.5 15.5 12 12l3.5 3.5" />
  </Icon>
);

export const Upload = (p: IconProps) => (
  <Icon {...p}>
    <path d="M12 15V4M7.5 8.5 12 4l4.5 4.5M5 15v3a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2v-3" />
  </Icon>
);

export const Home = (p: IconProps) => (
  <Icon {...p}>
    <path d="M4 11 12 4l8 7M6 9.5V20h12V9.5" />
  </Icon>
);

export const FileIcon = (p: IconProps) => (
  <Icon {...p}>
    <path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8l-5-5Z" />
    <path d="M14 3v5h5M9 13h6M9 17h4" />
  </Icon>
);

export const Shield = (p: IconProps) => (
  <Icon {...p}>
    <path d="M12 3 4.5 6v5.5c0 4.6 3.2 8.3 7.5 9.5 4.3-1.2 7.5-4.9 7.5-9.5V6L12 3Z" />
    <path d="M9 12h6" />
  </Icon>
);

export const Hash = (p: IconProps) => (
  <Icon {...p}>
    <path d="M5 9h14M5 15h14M10 4 8 20M16 4l-2 16" />
  </Icon>
);

export const Info = (p: IconProps) => (
  <Icon {...p}>
    <circle cx="12" cy="12" r="9" />
    <path d="M12 11v5M12 8h.01" />
  </Icon>
);

export const Alert = (p: IconProps) => (
  <Icon {...p}>
    <path d="M10.3 4.2 2.6 18a2 2 0 0 0 1.7 3h15.4a2 2 0 0 0 1.7-3L13.7 4.2a2 2 0 0 0-3.4 0Z" />
    <path d="M12 9.5v4.5M12 17.4h.01" />
  </Icon>
);

export const Refresh = (p: IconProps) => (
  <Icon {...p}>
    <path d="M20 11a8 8 0 0 0-14.5-4.5L4 8M4 4v4h4M4 13a8 8 0 0 0 14.5 4.5L20 16M20 20v-4h-4" />
  </Icon>
);

export const Database = (p: IconProps) => (
  <Icon {...p}>
    <ellipse cx="12" cy="6" rx="7" ry="3" />
    <path d="M5 6v12c0 1.7 3.1 3 7 3s7-1.3 7-3V6M5 12c0 1.7 3.1 3 7 3s7-1.3 7-3" />
  </Icon>
);

export const Custody = (p: IconProps) => (
  <Icon {...p}>
    <circle cx="6" cy="6" r="2.2" />
    <circle cx="6" cy="18" r="2.2" />
    <circle cx="18" cy="12" r="2.2" />
    <path d="M6 8.2v7.6M8 6.8l8 4M8 17.2l8-4" />
  </Icon>
);

export const Filter = (p: IconProps) => (
  <Icon {...p}>
    <path d="M4 5h16l-6 7.5V19l-4 1.5v-8L4 5Z" />
  </Icon>
);

export const Activity = (p: IconProps) => (
  <Icon {...p}>
    <path d="M3 12h4l3-8 4 16 3-8h4" />
  </Icon>
);

export const ScanSearch = (p: IconProps) => (
  <Icon {...p}>
    <path d="M4 8V6a2 2 0 0 1 2-2h2M16 4h2a2 2 0 0 1 2 2v2M20 16v2a2 2 0 0 1-2 2h-2M8 20H6a2 2 0 0 1-2-2v-2" />
    <circle cx="11.5" cy="11.5" r="3.5" />
    <path d="m16 16-2-2" />
  </Icon>
);

export const LayoutGrid = (p: IconProps) => (
  <Icon {...p}>
    <rect x="4" y="4" width="7" height="7" rx="1.5" />
    <rect x="13" y="4" width="7" height="7" rx="1.5" />
    <rect x="4" y="13" width="7" height="7" rx="1.5" />
    <rect x="13" y="13" width="7" height="7" rx="1.5" />
  </Icon>
);

export const Timeline = (p: IconProps) => (
  <Icon {...p}>
    <path d="M4 6h10M4 12h16M4 18h7M17 4v4M9 10v4M14 16v4" />
  </Icon>
);

export const GraphIcon = (p: IconProps) => (
  <Icon {...p}>
    <circle cx="5.5" cy="12" r="2.3" />
    <circle cx="18.5" cy="5.5" r="2.3" />
    <circle cx="18.5" cy="18.5" r="2.3" />
    <path d="m7.6 11 8.8-4.4M7.6 13l8.8 4.4" />
  </Icon>
);

export const ReportIcon = (p: IconProps) => (
  <Icon {...p}>
    <path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8l-5-5Z" />
    <path d="M14 3v5h5M9 17v-3M12 17v-5M15 17v-2" />
  </Icon>
);

export const Folder = (p: IconProps) => (
  <Icon {...p}>
    <path d="M3 7a2 2 0 0 1 2-2h4l2 2.5h8a2 2 0 0 1 2 2V18a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7Z" />
  </Icon>
);

export const Globe = (p: IconProps) => (
  <Icon {...p}>
    <circle cx="12" cy="12" r="9" />
    <path d="M3 12h18M12 3c2.5 2.6 3.8 5.6 3.8 9S14.5 18.4 12 21c-2.5-2.6-3.8-5.6-3.8-9S9.5 5.6 12 3Z" />
  </Icon>
);

export const Message = (p: IconProps) => (
  <Icon {...p}>
    <path d="M4 5h16v11H9l-4 3.5V16H4V5Z" />
  </Icon>
);

export const Terminal = (p: IconProps) => (
  <Icon {...p}>
    <rect x="3" y="4.5" width="18" height="15" rx="2" />
    <path d="m7 10 3 2.5L7 15M12.5 15H17" />
  </Icon>
);

export const ImageIcon = (p: IconProps) => (
  <Icon {...p}>
    <rect x="3.5" y="4.5" width="17" height="15" rx="2" />
    <circle cx="9" cy="10" r="1.6" />
    <path d="m20 16-4.5-4.5L7 20" />
  </Icon>
);

export const Network = (p: IconProps) => (
  <Icon {...p}>
    <rect x="9" y="3" width="6" height="5" rx="1" />
    <rect x="3" y="16" width="6" height="5" rx="1" />
    <rect x="15" y="16" width="6" height="5" rx="1" />
    <path d="M12 8v4M6 16v-4h12v4" />
  </Icon>
);

export const User = (p: IconProps) => (
  <Icon {...p}>
    <circle cx="12" cy="8" r="3.6" />
    <path d="M5 20c.8-3.6 3.6-5.5 7-5.5s6.2 1.9 7 5.5" />
  </Icon>
);

export const LaptopIcon = (p: IconProps) => (
  <Icon {...p}>
    <rect x="4.5" y="5" width="15" height="10.5" rx="1.5" />
    <path d="M2.5 19h19" />
  </Icon>
);

export const MapPin = (p: IconProps) => (
  <Icon {...p}>
    <path d="M12 21s-6.5-5.6-6.5-11a6.5 6.5 0 0 1 13 0c0 5.4-6.5 11-6.5 11Z" />
    <circle cx="12" cy="10" r="2.3" />
  </Icon>
);

export const ArrowRight = (p: IconProps) => (
  <Icon {...p}>
    <path d="M5 12h14M13 6l6 6-6 6" />
  </Icon>
);

export const Clock = (p: IconProps) => (
  <Icon {...p}>
    <circle cx="12" cy="12" r="9" />
    <path d="M12 7v5l3 2" />
  </Icon>
);

export const CircleCheck = (p: IconProps) => (
  <Icon {...p}>
    <circle cx="12" cy="12" r="9" />
    <path d="m8 12.3 2.7 2.7L16 9.5" />
  </Icon>
);

export const VideoIcon = (p: IconProps) => (
  <Icon {...p}>
    <rect x="3" y="6" width="13" height="12" rx="2" />
    <path d="m16 10.5 5-3v9l-5-3" />
  </Icon>
);

export const AudioWave = (p: IconProps) => (
  <Icon {...p}>
    <path d="M4 10v4M8 7v10M12 4v16M16 8v8M20 11v2" />
  </Icon>
);

export const Braces = (p: IconProps) => (
  <Icon {...p}>
    <path d="M8 4H7a2 2 0 0 0-2 2v4a2 2 0 0 1-2 2 2 2 0 0 1 2 2v4a2 2 0 0 0 2 2h1M16 4h1a2 2 0 0 1 2 2v4a2 2 0 0 0 2 2 2 2 0 0 0-2 2v4a2 2 0 0 1-2 2h-1" />
  </Icon>
);

export const TableIcon = (p: IconProps) => (
  <Icon {...p}>
    <rect x="3.5" y="4.5" width="17" height="15" rx="2" />
    <path d="M3.5 9.5h17M3.5 14.5h17M9.5 9.5v10" />
  </Icon>
);

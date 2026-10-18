// Line icons for the landing page, drawn to match the reference's thin outline style.
import type { ReactNode, SVGProps } from "react";

type IconProps = SVGProps<SVGSVGElement> & { size?: number | string };

const Icon = ({ size = 24, children, strokeWidth = 1.6, ...props }: IconProps & { children: ReactNode }) => (
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

export const LogoMark = ({ size = 40, ...props }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 48 44" fill="none" aria-hidden="true" {...props}>
    <path d="M24 3 45 40H3L24 3Z" stroke="currentColor" strokeWidth="3.6" strokeLinejoin="round" />
    <path d="M24 17 34 34H14l10-17Z" stroke="currentColor" strokeWidth="2.4" strokeLinejoin="round" />
    <path d="M20 34 27 22" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" />
  </svg>
);

export const ArrowRight = (props: IconProps) => (
  <Icon {...props}>
    <path d="M5 12h14M13 6l6 6-6 6" />
  </Icon>
);

export const PlayCircle = (props: IconProps) => (
  <Icon {...props}>
    <circle cx="12" cy="12" r="10" />
    <path d="m10 8.5 5.5 3.5-5.5 3.5v-7Z" />
  </Icon>
);

export const Layers = (props: IconProps) => (
  <Icon {...props}>
    <path d="m12 3 9 4.5-9 4.5-9-4.5L12 3Z" />
    <path d="m3 12 9 4.5 9-4.5" />
    <path d="m3 16.5 9 4.5 9-4.5" />
  </Icon>
);

export const NetworkNodes = (props: IconProps) => (
  <Icon {...props}>
    <circle cx="5" cy="5" r="2.2" />
    <circle cx="19" cy="5" r="2.2" />
    <circle cx="5" cy="19" r="2.2" />
    <circle cx="19" cy="19" r="2.2" />
    <circle cx="12" cy="12" r="2.2" />
    <path d="M7 5h10M5 7v10M7.2 7.2l3.2 3.2M13.6 13.6l3.2 3.2M7 19h10M19 7v10" />
  </Icon>
);

export const LinkChain = (props: IconProps) => (
  <Icon {...props}>
    <path d="M10 14a4.5 4.5 0 0 0 6.4 0l3.2-3.2a4.5 4.5 0 0 0-6.4-6.4L12 5.6" />
    <path d="M14 10a4.5 4.5 0 0 0-6.4 0l-3.2 3.2a4.5 4.5 0 0 0 6.4 6.4L12 18.4" />
  </Icon>
);

export const FileText = (props: IconProps) => (
  <Icon {...props}>
    <path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8l-5-5Z" />
    <path d="M14 3v5h5M9 13h6M9 17h6M9 9h2" />
  </Icon>
);

export const Laptop = (props: IconProps) => (
  <Icon {...props}>
    <rect x="4" y="5" width="16" height="11" rx="1.5" />
    <path d="M2 19h20" />
  </Icon>
);

export const ChatBubble = (props: IconProps) => (
  <Icon {...props}>
    <path d="M4 5h16v11H9l-4 3.5V16H4V5Z" />
    <path d="M8.5 10.5h.01M12 10.5h.01M15.5 10.5h.01" strokeWidth={2.4} />
  </Icon>
);

export const EventBox = (props: IconProps) => (
  <Icon {...props}>
    <rect x="3.5" y="3.5" width="17" height="17" rx="2.5" />
    <path d="m7.5 13.5 3 3 6-8" />
  </Icon>
);

export const Monitor = (props: IconProps) => (
  <Icon {...props}>
    <rect x="4.5" y="5" width="15" height="11" rx="1.5" />
    <path d="M9 19.5h6M12 16v3.5" />
    <path d="M8 10.5h3l1.5-2 2 4 1-2" />
  </Icon>
);

export const AlertTriangle = (props: IconProps) => (
  <Icon {...props}>
    <path d="M10.3 4.2 2.6 18a2 2 0 0 0 1.7 3h15.4a2 2 0 0 0 1.7-3L13.7 4.2a2 2 0 0 0-3.4 0Z" />
    <path d="M12 9.5v4.5M12 17.4h.01" strokeWidth={2.2} />
  </Icon>
);

export const CheckCircle = (props: IconProps) => (
  <Icon {...props}>
    <circle cx="12" cy="12" r="9" />
    <path d="m8 12.3 2.7 2.7L16 9.5" />
  </Icon>
);

export const Folder = (props: IconProps) => (
  <Icon {...props}>
    <path d="M3 7a2 2 0 0 1 2-2h4l2 2.5h8a2 2 0 0 1 2 2V18a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7Z" />
    <path d="M3 10.5h18" />
  </Icon>
);

export const ShieldCheck = (props: IconProps) => (
  <Icon {...props}>
    <path d="M12 3 4.5 6v5.5c0 4.6 3.2 8.3 7.5 9.5 4.3-1.2 7.5-4.9 7.5-9.5V6L12 3Z" />
    <path d="m8.7 12 2.4 2.4 4.3-4.6" />
  </Icon>
);

export const Flag = (props: IconProps) => (
  <Icon {...props}>
    <path d="M5 21V4M5 4h11l-2 3.5L16 11H5" />
  </Icon>
);

export const Menu = (props: IconProps) => (
  <Icon {...props}>
    <path d="M4 7h16M4 12h16M4 17h16" />
  </Icon>
);

/** Wireframe laptop drawn in perspective for the device card. */
export const LaptopWireframe = (props: SVGProps<SVGSVGElement>) => (
  <svg viewBox="0 0 160 110" fill="none" aria-hidden="true" {...props}>
    <g stroke="currentColor" strokeWidth="1.1" strokeLinejoin="round">
      <path d="M44 8 150 2 142 66 38 74Z" opacity="0.85" />
      <path d="M50 14 143 9 136 61 45 67Z" opacity="0.4" />
      <path d="M38 74 142 66 158 82 18 94Z" opacity="0.9" />
      <path d="M18 94 158 82 158 86 18 98Z" opacity="0.6" />
      <path d="M52 78 130 72M48 82 134 75M44 86 138 79" opacity="0.35" />
      <path d="M76 90 104 87.5" opacity="0.5" />
    </g>
  </svg>
);
